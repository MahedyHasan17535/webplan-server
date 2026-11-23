
import express from 'express';
import cors from 'cors';
import 'dotenv/config';
import { MongoClient, ObjectId } from 'mongodb';
import Stripe from 'stripe';

if (!process.env.MONGODB_URI) {
    throw new Error('MONGODB_URI is missing. Add it to your .env file or deployment environment variables.');
}

if (!process.env.STRIPE_SECRET_KEY) {
    throw new Error('STRIPE_SECRET_KEY is missing. Add it to your .env file or deployment environment variables.');
}

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const app = express();
const port = process.env.PORT || 5000;

// middleware
const allowedOrigins = (process.env.CLIENT_URL || 'http://localhost:3000')
    .split(',')
    .map((origin) => origin.trim());

app.use(cors({ origin: allowedOrigins }));

// Stripe needs the raw body to verify webhook signatures, so skip json parsing there.
app.use((req, res, next) => {
    if (req.originalUrl === '/payments/webhook') {
        next();
        return;
    }
    express.json()(req, res, next);
});

const client = new MongoClient(process.env.MONGODB_URI);

export async function connectToMongoDB() {
    try {
        await client.connect();
        console.log('You successfully connected to MongoDB!');
        return client;
    } catch (err) {
        console.error('MongoDB connection failed:', err);
        throw err;
    }
}

const connectedClient = await connectToMongoDB();

// MongoDB database name
const database = connectedClient.db('wedplandb');

// `user` and `session` are managed by Better Auth.
const users = database.collection('user');
const sessions = database.collection('session');
const services = database.collection('services');
const bookings = database.collection('bookings');
const transactions = database.collection('transactions');

app.get('/', (req, res) => {
    res.send('wedplan is planning')
})

// constants
const CATEGORIES = [
    'Photography & Videography',
    'Wedding Venues',
    'Decoration & Florist',
    'Catering Services',
    'Makeup & Styling',
    'Wedding Fashion',
];

const FREE_SERVICE_LIMIT = 3;
const PREMIUM_PRICE_CENTS = 2900;

// helpers
const isValidId = (id) => /^[0-9a-fA-F]{24}$/.test(String(id));

const escapeRegex = (text) => String(text).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const isHttpUrl = (value) => /^https?:\/\/\S+$/i.test(String(value));

// Premium only counts while the paid period has not ended.
const getEffectivePlan = (user) => {
    const expiresAt = user.subscriptionExpiresAt;

    if (user.subscriptionPlan === 'premium' && expiresAt && new Date(expiresAt) > new Date()) {
        return 'premium';
    }

    return 'free';
}

const publicUser = (user) => ({
    _id: user._id,
    name: user.name,
    email: user.email,
    image: user.image || null,
    role: user.role,
    isBlocked: Boolean(user.isBlocked),
    businessName: user.businessName || '',
    subscriptionPlan: getEffectivePlan(user),
    subscriptionExpiresAt: user.subscriptionExpiresAt || null,
    createdAt: user.createdAt,
})


// Aggregation stages that attach one referenced document (by string id) to each row.
const joinOne = (from, localField, as, fields) => {
    const picked = Object.fromEntries(
        fields.map((field) => [field, `$$doc.${field}`])
    );

    return [
        {
            $lookup: {
                from,
                let: {
                    refId: { $toObjectId: `$${localField}` }
                },
                pipeline: [
                    {
                        $match: {
                            $expr: {
                                $eq: ['$_id', '$$refId']
                            }
                        }
                    },
                    { $limit: 1 }
                ],
                as: `${as}Docs`
            }
        },
        {
            $addFields: {
                [as]: {
                    $let: {
                        vars: {
                            doc: {
                                $arrayElemAt: [`$${as}Docs`, 0]
                            }
                        },
                        in: picked
                    }
                }
            }
        },
        {
            $project: {
                [`${as}Docs`]: 0
            }
        }
    ];
};

const vendorFields = ['_id', 'name', 'image', 'businessName', 'subscriptionPlan', 'subscriptionExpiresAt'];

const verifyToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        res.status(401).send({ message: 'Unauthorized' });
        return;
    }

    const token = authHeader.split(' ')[1];

    if (!token) {
        res.status(401).send({ message: 'Unauthorized' });
        return;
    }

    const query = { token };
    const session = await sessions.findOne(query);

    if (!session) {
        res.status(401).send({ message: 'Unauthorized' });
        return;
    }

    // expired sessions must be rejected even if the row still exists
    if (!session.expiresAt || new Date(session.expiresAt) < new Date()) {
        res.status(401).send({ message: 'Session expired' });
        return;
    }

    if (!isValidId(session.userId)) {
        res.status(401).send({ message: 'Unauthorized' });
        return;
    }

    const userQuery = { _id: new ObjectId(String(session.userId)) };
    const user = await users.findOne(userQuery);

    if (!user) {
        res.status(401).send({ message: 'Unauthorized' });
        return;
    }

    if (user.isBlocked) {
        res.status(403).send({ message: 'Your account has been blocked' });
        return;
    }

    req.user = user;
    next();
}

// must call these middlewares after verifyToken
const verifyCustomer = async (req, res, next) => {
    if (req.user.role !== 'customer') {
        res.status(403).send({ message: 'Forbidden' });
        return;
    }

    next();
}

const verifyVendor = async (req, res, next) => {
    if (req.user.role !== 'vendor') {
        res.status(403).send({ message: 'Forbidden' });
        return;
    }

    next();
}

const verifyAdmin = async (req, res, next) => {
    if (req.user.role !== 'admin') {
        res.status(403).send({ message: 'Forbidden' });
        return;
    }

    next();
}

// rejects malformed :id params before they reach ObjectId
const validateIdParam = (req, res, next) => {
    if (!isValidId(req.params.id)) {
        res.status(400).send({ message: 'Invalid id' });
        return;
    }

    next();
}

// users related apis
app.get('/users/me', verifyToken, async (req, res) => {
    const user = req.user;

    // lazily downgrade vendors whose paid period has ended
    if (user.subscriptionPlan === 'premium' && getEffectivePlan(user) === 'free') {
        await users.updateOne({ _id: user._id }, { $set: { subscriptionPlan: 'free' } });
        await enforceFreeLimit(user._id.toString());
    }

    res.send(publicUser(user));
})

app.patch('/users/me', verifyToken, async (req, res) => {
    // only these fields can be edited - role and subscription are never taken from the client
    const updates = {};

    if (req.body.name !== undefined) {
        const name = String(req.body.name).trim();

        if (name.length < 2) {
            return res.status(400).send({ message: 'Name must be at least 2 characters' });
        }

        updates.name = name;
    }

    if (req.body.image !== undefined) {
        const image = String(req.body.image).trim();

        if (image && !isHttpUrl(image)) {
            return res.status(400).send({ message: 'Profile image must be a valid URL' });
        }

        updates.image = image || null;
    }

    if (req.body.businessName !== undefined && req.user.role === 'vendor') {
        updates.businessName = String(req.body.businessName).trim().slice(0, 80);
    }

    if (Object.keys(updates).length === 0) {
        return res.status(400).send({ message: 'Nothing to update' });
    }

    updates.updatedAt = new Date();

    await users.updateOne({ _id: req.user._id }, { $set: updates });
    const updated = await users.findOne({ _id: req.user._id });

    res.send({ success: true, user: publicUser(updated) });
})

// admin only user management
app.get('/users', verifyToken, verifyAdmin, async (req, res) => {
    const query = {};

    if (req.query.role && ['customer', 'vendor', 'admin'].includes(req.query.role)) {
        query.role = req.query.role;
    }

    if (req.query.search) {
        const search = { $regex: escapeRegex(req.query.search), $options: 'i' };
        query.$or = [{ name: search }, { email: search }];
    }

    const cursor = users.find(query).sort({ createdAt: -1 });
    const result = await cursor.toArray();

    res.send(result.map(publicUser));
})

app.get('/users/:id', verifyToken, verifyAdmin, validateIdParam, async (req, res) => {
    const query = { _id: new ObjectId(req.params.id) };
    const user = await users.findOne(query);

    if (!user) {
        return res.status(404).send({ message: 'User not found' });
    }

    res.send(publicUser(user));
})

app.patch('/users/:id/block', verifyToken, verifyAdmin, validateIdParam, async (req, res) => {
    const id = req.params.id;

    if (typeof req.body.isBlocked !== 'boolean') {
        return res.status(400).send({ message: 'isBlocked must be true or false' });
    }

    if (id === req.user._id.toString()) {
        return res.status(400).send({ message: 'You cannot block yourself' });
    }

    const target = await users.findOne({ _id: new ObjectId(id) });

    if (!target) {
        return res.status(404).send({ message: 'User not found' });
    }

    if (target.role === 'admin') {
        return res.status(403).send({ message: 'Admin accounts cannot be blocked' });
    }

    const updatedDoc = {
        $set: {
            isBlocked: req.body.isBlocked,
        }
    }

    const result = await users.updateOne({ _id: target._id }, updatedDoc);

    // end every active session of a freshly blocked user
    if (req.body.isBlocked) {
        await sessions.deleteMany({ userId: { $in: [id, target._id] } });
    }

    res.send(result);
})

// services related apis
const getActiveServiceCount = (vendorId) => {
    const query = { vendorId, isActive: true, status: { $ne: 'rejected' } };
    return services.countDocuments(query);
}

// free vendors are capped, premium vendors are unlimited
const canActivateAnotherService = async (user) => {
    if (getEffectivePlan(user) === 'premium') {
        return true;
    }

    const count = await getActiveServiceCount(user._id.toString());
    return count < FREE_SERVICE_LIMIT;
}

// called when a vendor falls back to the free plan: keep the 3 oldest services active
async function enforceFreeLimit(vendorId) {
    const active = await services
        .find({ vendorId, isActive: true, status: { $ne: 'rejected' } })
        .sort({ createdAt: 1 })
        .toArray();

    const extraIds = active.slice(FREE_SERVICE_LIMIT).map((service) => service._id);

    if (extraIds.length > 0) {
        await services.updateMany({ _id: { $in: extraIds } }, { $set: { isActive: false } });
    }
}

const validateServicePayload = (body) => {
    const serviceName = String(body.serviceName || '').trim();
    const category = String(body.category || '').trim();
    const description = String(body.description || '').trim();
    const location = String(body.location || '').trim();
    const price = Number(body.price);
    const images = Array.isArray(body.images) ? body.images.map(String) : [];

    let message = null;

    if (serviceName.length < 3) {
        message = 'Service name must be at least 3 characters';
    } else if (!CATEGORIES.includes(category)) {
        message = 'Please select a valid category';
    } else if (description.length < 20) {
        message = 'Description must be at least 20 characters';
    } else if (!Number.isFinite(price) || price <= 0) {
        message = 'Price must be a positive number';
    } else if (location.length < 2) {
        message = 'Location is required';
    } else if (images.length < 1 || images.length > 5 || !images.every(isHttpUrl)) {
        message = 'Add between 1 and 5 valid service images';
    }

    return { message, data: { serviceName, category, description, price, location, images } };
}

app.get('/services/categories', async (req, res) => {
    const pipeline = [
        { $match: { status: 'approved', isActive: true } },
        { $group: { _id: '$category', count: { $sum: 1 } } },
    ];

    const rows = await services.aggregate(pipeline).toArray();
    const counts = Object.fromEntries(rows.map((row) => [row._id, row.count]));

    res.send(CATEGORIES.map((name) => ({ name, count: counts[name] || 0 })));
})

// only approved + active services are public
app.get('/services', async (req, res) => {
    const { search, category, location, sort } = req.query;
    const query = { status: 'approved', isActive: true };

    if (category) {
        query.category = String(category);
    }

    if (location) {
        query.location = { $regex: escapeRegex(location), $options: 'i' };
    }

    if (search) {
        query.serviceName = { $regex: escapeRegex(search), $options: 'i' };
    }

    const sortOptions = {
        price_asc: { price: 1 },
        price_desc: { price: -1 },
    };

    const limit = Math.min(Number(req.query.limit) || 100, 100);

    const pipeline = [
        { $match: query },
        { $sort: sortOptions[sort] || { createdAt: -1 } },
        { $limit: limit },
        ...joinOne('user', 'vendorId', 'vendor', vendorFields),
    ];

    const result = await services.aggregate(pipeline).toArray();
    res.send(result);
})

// vendor's own services (all statuses) - must stay above /services/:id
app.get('/services/mine', verifyToken, verifyVendor, async (req, res) => {
    const pipeline = [
        { $match: { vendorId: req.user._id.toString() } },
        { $sort: { createdAt: -1 } },
    ];

    const result = await services.aggregate(pipeline).toArray();
    res.send(result);
})

app.get('/services/:id', verifyToken, validateIdParam, async (req, res) => {
    const id = req.params.id;

    const pipeline = [
        { $match: { _id: new ObjectId(id) } },
        ...joinOne('user', 'vendorId', 'vendor', [...vendorFields, 'email']),
    ];

    const service = await services.aggregate(pipeline).next();

    if (!service) {
        return res.status(404).send({ message: 'Service not found' });
    }

    const isOwner = service.vendorId === req.user._id.toString();
    const isPublic = service.status === 'approved' && service.isActive;

    if (!isPublic && !isOwner && req.user.role !== 'admin') {
        return res.status(404).send({ message: 'Service not found' });
    }

    res.send(service);
})

app.post('/services', verifyToken, verifyVendor, async (req, res) => {
    const { message, data } = validateServicePayload(req.body);

    if (message) {
        return res.status(400).send({ message });
    }

    if (!(await canActivateAnotherService(req.user))) {
        return res.status(402).send({
            message: `Free plan allows ${FREE_SERVICE_LIMIT} active services. Upgrade to Premium to publish more.`,
        });
    }

    const service = {
        ...data,
        vendorId: req.user._id.toString(),
        status: 'pending',
        isActive: true,
        createdAt: new Date(),
    };

    const result = await services.insertOne(service);
    res.status(201).send(result);
})

app.patch('/services/:id', verifyToken, verifyVendor, validateIdParam, async (req, res) => {
    const query = { _id: new ObjectId(req.params.id) };
    const service = await services.findOne(query);

    if (!service) {
        return res.status(404).send({ message: 'Service not found' });
    }

    // ownership check: vendors can only touch their own services
    if (service.vendorId !== req.user._id.toString()) {
        return res.status(403).send({ message: 'Forbidden' });
    }

    const { message, data } = validateServicePayload(req.body);

    if (message) {
        return res.status(400).send({ message });
    }

    const updatedDoc = {
        $set: {
            ...data,
            // an edited rejected service goes back to review
            status: service.status === 'rejected' ? 'pending' : service.status,
            updatedAt: new Date(),
        }
    }

    const result = await services.updateOne(query, updatedDoc);
    res.send(result);
})

app.patch('/services/:id/availability', verifyToken, verifyVendor, validateIdParam, async (req, res) => {
    const query = { _id: new ObjectId(req.params.id) };
    const service = await services.findOne(query);

    if (!service) {
        return res.status(404).send({ message: 'Service not found' });
    }

    if (service.vendorId !== req.user._id.toString()) {
        return res.status(403).send({ message: 'Forbidden' });
    }

    if (typeof req.body.isActive !== 'boolean') {
        return res.status(400).send({ message: 'isActive must be true or false' });
    }

    if (req.body.isActive && !service.isActive && !(await canActivateAnotherService(req.user))) {
        return res.status(402).send({
            message: `Free plan allows ${FREE_SERVICE_LIMIT} active services. Upgrade to Premium to publish more.`,
        });
    }

    const updatedDoc = {
        $set: {
            isActive: req.body.isActive,
        }
    }

    const result = await services.updateOne(query, updatedDoc);
    res.send(result);
})

// vendor (owner) or admin can delete
app.delete('/services/:id', verifyToken, validateIdParam, async (req, res) => {
    if (req.user.role !== 'vendor' && req.user.role !== 'admin') {
        return res.status(403).send({ message: 'Forbidden' });
    }

    const query = { _id: new ObjectId(req.params.id) };
    const service = await services.findOne(query);

    if (!service) {
        return res.status(404).send({ message: 'Service not found' });
    }

    if (req.user.role === 'vendor' && service.vendorId !== req.user._id.toString()) {
        return res.status(403).send({ message: 'Forbidden' });
    }

    const result = await services.deleteOne(query);

    // pending requests for a removed service can no longer be fulfilled
    await bookings.updateMany(
        { serviceId: req.params.id, status: 'pending' },
        { $set: { status: 'cancelled' } }
    );

    res.send(result);
})

// admin service moderation
app.get('/admin/services', verifyToken, verifyAdmin, async (req, res) => {
    const query = {};

    if (['pending', 'approved', 'rejected'].includes(req.query.status)) {
        query.status = req.query.status;
    }

    if (req.query.category) {
        query.category = String(req.query.category);
    }

    if (req.query.search) {
        query.serviceName = { $regex: escapeRegex(req.query.search), $options: 'i' };
    }

    const pipeline = [
        { $match: query },
        { $sort: { createdAt: -1 } },
        ...joinOne('user', 'vendorId', 'vendor', vendorFields),
    ];

    const result = await services.aggregate(pipeline).toArray();
    res.send(result);
})

app.patch('/admin/services/:id/status', verifyToken, verifyAdmin, validateIdParam, async (req, res) => {
    const status = req.body.status;

    if (!['pending', 'approved', 'rejected'].includes(status)) {
        return res.status(400).send({ message: 'Invalid status' });
    }

    const query = { _id: new ObjectId(req.params.id) };

    const updatedDoc = {
        $set: {
            status,
            reviewedAt: new Date(),
        }
    }

    const result = await services.updateOne(query, updatedDoc);

    if (result.matchedCount === 0) {
        return res.status(404).send({ message: 'Service not found' });
    }

    res.send(result);
})

// bookings related apis
const todayString = () => new Date().toISOString().slice(0, 10);

const isValidEventDate = (value) => {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(String(value))) {
        return false;
    }

    const date = new Date(`${value}T00:00:00.000Z`);
    return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === value;
}

const bookingJoins = [
    ...joinOne('services', 'serviceId', 'service', ['_id', 'serviceName', 'images', 'price', 'location', 'category']),
    ...joinOne('user', 'vendorId', 'vendor', ['_id', 'name', 'image', 'businessName', 'email']),
    ...joinOne('user', 'customerId', 'customer', ['_id', 'name', 'image', 'email']),
];

app.post('/bookings', verifyToken, verifyCustomer, async (req, res) => {
    const { serviceId, eventDate, eventLocation } = req.body;
    const message = String(req.body.message || '').trim();

    if (!isValidId(serviceId)) {
        return res.status(400).send({ message: 'Invalid service id' });
    }

    if (!isValidEventDate(eventDate)) {
        return res.status(400).send({ message: 'Event date must be a valid date' });
    }

    if (eventDate < todayString()) {
        return res.status(400).send({ message: 'Event date cannot be in the past' });
    }

    if (String(eventLocation || '').trim().length < 3) {
        return res.status(400).send({ message: 'Event location is required' });
    }

    if (message.length > 1000) {
        return res.status(400).send({ message: 'Message is too long' });
    }

    const service = await services.findOne({ _id: new ObjectId(serviceId) });

    if (!service) {
        return res.status(404).send({ message: 'Service not found' });
    }

    // vendorId always comes from the service, never from the client
    const customerId = req.user._id.toString();

    if (service.vendorId === customerId) {
        return res.status(403).send({ message: 'You cannot book your own service' });
    }

    if (service.status !== 'approved' || !service.isActive) {
        return res.status(400).send({ message: 'This service is not available for booking' });
    }

    // no duplicate active request by the same customer, and no double booking on an accepted date
    const duplicateQuery = {
        serviceId,
        eventDate,
        $or: [
            { customerId, status: { $in: ['pending', 'accepted'] } },
            { status: 'accepted' },
        ],
    };

    const duplicate = await bookings.findOne(duplicateQuery);

    if (duplicate) {
        return res.status(409).send({
            message: 'There is already an active booking request for this service on that date',
        });
    }

    const booking = {
        serviceId,
        vendorId: service.vendorId,
        customerId,
        eventDate,
        eventLocation: String(eventLocation).trim(),
        message,
        status: 'pending',
        createdAt: new Date(),
    };

    const result = await bookings.insertOne(booking);
    res.status(201).send(result);
})

app.get('/bookings/mine', verifyToken, verifyCustomer, async (req, res) => {
    const pipeline = [
        { $match: { customerId: req.user._id.toString() } },
        { $sort: { createdAt: -1 } },
        ...bookingJoins,
    ];

    const result = await bookings.aggregate(pipeline).toArray();
    res.send(result);
})

app.get('/bookings/vendor', verifyToken, verifyVendor, async (req, res) => {
    const pipeline = [
        { $match: { vendorId: req.user._id.toString() } },
        { $sort: { createdAt: -1 } },
        ...bookingJoins,
    ];

    const result = await bookings.aggregate(pipeline).toArray();
    res.send(result);
})

app.get('/bookings/:id', verifyToken, validateIdParam, async (req, res) => {
    const pipeline = [
        { $match: { _id: new ObjectId(req.params.id) } },
        ...bookingJoins,
    ];

    const booking = await bookings.aggregate(pipeline).next();

    if (!booking) {
        return res.status(404).send({ message: 'Booking not found' });
    }

    const userId = req.user._id.toString();
    const isParty = booking.customerId === userId || booking.vendorId === userId;

    if (!isParty && req.user.role !== 'admin') {
        return res.status(403).send({ message: 'Forbidden' });
    }

    res.send(booking);
})

// vendor accepts or rejects - only a pending request owned by this vendor
app.patch('/bookings/:id/status', verifyToken, verifyVendor, validateIdParam, async (req, res) => {
    const status = req.body.status;

    if (!['accepted', 'rejected'].includes(status)) {
        return res.status(400).send({ message: 'Status must be accepted or rejected' });
    }

    const booking = await bookings.findOne({ _id: new ObjectId(req.params.id) });

    if (!booking) {
        return res.status(404).send({ message: 'Booking not found' });
    }

    if (booking.vendorId !== req.user._id.toString()) {
        return res.status(403).send({ message: 'Forbidden' });
    }

    // the status filter makes the transition atomic: a processed request cannot be processed again
    const query = { _id: booking._id, status: 'pending' };

    const updatedDoc = {
        $set: {
            status,
            processedAt: new Date(),
        }
    }

    const result = await bookings.updateOne(query, updatedDoc);

    if (result.matchedCount === 0) {
        return res.status(409).send({ message: 'Only pending requests can be accepted or rejected' });
    }

    res.send(result);
})

// customer cancels their own pending request
app.patch('/bookings/:id/cancel', verifyToken, verifyCustomer, validateIdParam, async (req, res) => {
    const booking = await bookings.findOne({ _id: new ObjectId(req.params.id) });

    if (!booking) {
        return res.status(404).send({ message: 'Booking not found' });
    }

    if (booking.customerId !== req.user._id.toString()) {
        return res.status(403).send({ message: 'Forbidden' });
    }

    const query = { _id: booking._id, status: 'pending' };

    const updatedDoc = {
        $set: {
            status: 'cancelled',
            processedAt: new Date(),
        }
    }

    const result = await bookings.updateOne(query, updatedDoc);

    if (result.matchedCount === 0) {
        return res.status(409).send({ message: 'Only pending requests can be cancelled' });
    }

    res.send(result);
})

// dashboard stats apis
app.get('/stats/vendor', verifyToken, verifyVendor, async (req, res) => {
    const vendorId = req.user._id.toString();

    const [totalServices, activeServices, pendingBookings, acceptedBookings] = await Promise.all([
        services.countDocuments({ vendorId }),
        services.countDocuments({ vendorId, status: 'approved', isActive: true }),
        bookings.countDocuments({ vendorId, status: 'pending' }),
        bookings.countDocuments({ vendorId, status: 'accepted' }),
    ]);

    res.send({
        totalServices,
        activeServices,
        pendingBookings,
        acceptedBookings,
        subscriptionPlan: getEffectivePlan(req.user),
    });
})

app.get('/stats/customer', verifyToken, verifyCustomer, async (req, res) => {
    const customerId = req.user._id.toString();

    const [total, pending, accepted, rejected] = await Promise.all([
        bookings.countDocuments({ customerId }),
        bookings.countDocuments({ customerId, status: 'pending' }),
        bookings.countDocuments({ customerId, status: 'accepted' }),
        bookings.countDocuments({ customerId, status: 'rejected' }),
    ]);

    res.send({ total, pending, accepted, rejected });
})

app.get('/stats/admin', verifyToken, verifyAdmin, async (req, res) => {
    const [totalUsers, totalVendors, totalCustomers, totalServices, pendingServices, totalTransactions] =
        await Promise.all([
            users.countDocuments({}),
            users.countDocuments({ role: 'vendor' }),
            users.countDocuments({ role: 'customer' }),
            services.countDocuments({}),
            services.countDocuments({ status: 'pending' }),
            transactions.countDocuments({}),
        ]);

    res.send({ totalUsers, totalVendors, totalCustomers, totalServices, pendingServices, totalTransactions });
})

// payments related apis
app.post('/payments/create-checkout-session', verifyToken, verifyVendor, async (req, res) => {
    // the vendor comes from the verified token, so nobody can start a session for another vendor
    const vendor = req.user;

    if (getEffectivePlan(vendor) === 'premium') {
        return res.status(409).send({ message: 'You already have an active Premium plan' });
    }

    const clientUrl = allowedOrigins[0];

    const session = await stripe.checkout.sessions.create({
        mode: 'subscription',
        line_items: [
            {
                price_data: {
                    currency: 'usd',
                    unit_amount: PREMIUM_PRICE_CENTS,
                    recurring: { interval: 'month' },
                    product_data: {
                        name: 'WedPlan Premium Vendor',
                        description: 'Unlimited services and the Premium Vendor badge',
                    },
                },
                quantity: 1,
            },
        ],
        customer_email: vendor.email,
        client_reference_id: vendor._id.toString(),
        metadata: { vendorId: vendor._id.toString(), plan: 'premium' },
        success_url: `${clientUrl}/payment/success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${clientUrl}/payment/cancel`,
    });

    res.send({ url: session.url });
})

const getPeriodEnd = async (subscriptionId) => {
    const fallback = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

    if (!subscriptionId) {
        return fallback;
    }

    const subscription = await stripe.subscriptions.retrieve(subscriptionId);

    // the period end moved onto the subscription item in newer Stripe API versions
    const seconds = subscription.current_period_end ?? subscription.items?.data?.[0]?.current_period_end;

    return seconds ? new Date(seconds * 1000) : fallback;
}

const activatePremium = async (session) => {
    const vendorId = session.metadata?.vendorId;

    if (session.payment_status !== 'paid' || !isValidId(vendorId)) {
        return;
    }

    // webhooks can be delivered more than once
    const existing = await transactions.findOne({ stripeSessionId: session.id });

    if (existing) {
        return;
    }

    const subscriptionId = session.subscription || null;

    const transaction = {
        vendorId,
        plan: 'premium',
        amount: (session.amount_total || 0) / 100,
        currency: session.currency,
        stripeSessionId: session.id,
        stripeSubscriptionId: subscriptionId,
        status: 'paid',
        createdAt: new Date(),
    };

    await transactions.insertOne(transaction);

    const updatedDoc = {
        $set: {
            subscriptionPlan: 'premium',
            subscriptionExpiresAt: await getPeriodEnd(subscriptionId),
        }
    }

    await users.updateOne({ _id: new ObjectId(vendorId) }, updatedDoc);
}

// renewal invoices extend the paid period
const renewPremium = async (invoice) => {
    const subscriptionId = invoice.subscription ?? invoice.parent?.subscription_details?.subscription;

    if (!subscriptionId || invoice.billing_reason === 'subscription_create') {
        return;
    }

    const first = await transactions.findOne({ stripeSubscriptionId: subscriptionId });

    if (!first || (await transactions.findOne({ stripeSessionId: invoice.id }))) {
        return;
    }

    await transactions.insertOne({
        vendorId: first.vendorId,
        plan: 'premium',
        amount: (invoice.amount_paid || 0) / 100,
        currency: invoice.currency,
        stripeSessionId: invoice.id,
        stripeSubscriptionId: subscriptionId,
        status: 'paid',
        createdAt: new Date(),
    });

    await users.updateOne(
        { _id: new ObjectId(first.vendorId) },
        { $set: { subscriptionPlan: 'premium', subscriptionExpiresAt: await getPeriodEnd(subscriptionId) } }
    );
}

// cancelled subscriptions fall back to the free plan
const cancelPremium = async (subscription) => {
    const first = await transactions.findOne({ stripeSubscriptionId: subscription.id });

    if (!first) {
        return;
    }

    await users.updateOne(
        { _id: new ObjectId(first.vendorId) },
        { $set: { subscriptionPlan: 'free', subscriptionExpiresAt: null } }
    );

    await enforceFreeLimit(first.vendorId);
}

// Premium is only ever activated from here, after the signature is verified.
app.post('/payments/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    let event;

    try {
        event = stripe.webhooks.constructEvent(
            req.body,
            req.headers['stripe-signature'],
            process.env.STRIPE_WEBHOOK_SECRET
        );
    } catch (err) {
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === 'checkout.session.completed') {
        await activatePremium(event.data.object);
    }

    if (event.type === 'invoice.paid') {
        await renewPremium(event.data.object);
    }

    if (event.type === 'customer.subscription.deleted') {
        await cancelPremium(event.data.object);
    }

    res.send({ received: true });
})

// transactions related apis (read only - payment records are written by the Stripe webhook only)
app.get('/transactions', verifyToken, verifyAdmin, async (req, res) => {
    const pipeline = [
        { $sort: { createdAt: -1 } },
        ...joinOne('user', 'vendorId', 'vendor', ['_id', 'name', 'email', 'businessName']),
    ];

    const result = await transactions.aggregate(pipeline).toArray();
    res.send(result);
})

app.get('/transactions/mine', verifyToken, verifyVendor, async (req, res) => {
    const query = { vendorId: req.user._id.toString() };

    const result = await transactions.find(query).sort({ createdAt: -1 }).toArray();
    res.send(result);
})

// the success page polls this until the webhook has recorded the payment
app.get('/payments/status', verifyToken, verifyVendor, async (req, res) => {
    const sessionId = String(req.query.session_id || '');

    if (!sessionId) {
        return res.status(400).send({ message: 'Session ID is required' });
    }

    const query = { stripeSessionId: sessionId, vendorId: req.user._id.toString() };
    const transaction = await transactions.findOne(query);

    if (!transaction) {
        return res.send({ status: 'pending' });
    }

    res.send({
        status: 'paid',
        amount: transaction.amount,
        currency: transaction.currency,
        plan: transaction.plan,
        subscriptionPlan: getEffectivePlan(req.user),
    });
})

// unknown routes
app.use((req, res) => {
    res.status(404).send({ message: 'Route not found' });
})

// any failed handler ends up here (Express 5 forwards rejected promises)
app.use((err, req, res, next) => {
    console.error(err);

    if (err.type === 'entity.parse.failed') {
        return res.status(400).send({ message: 'Invalid JSON body' });
    }

    res.status(500).send({ message: 'Internal server error' });
})

app.listen(port, () => {
    console.log(`wedplan is running on port ${port}`)
})

export default app;
