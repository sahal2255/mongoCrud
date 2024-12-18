const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const mongoose = require('mongoose');
const path = require('path');
const bcrypt=require('bcrypt')

const app = express();
const port = 3010;


// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
    secret: 'your-secret-key',
    resave: true,
    saveUninitialized: true
}));

// Connect to MongoDB
const uri = 'mongodb://localhost:27017/LoginDetails';
mongoose.connect(uri)
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('Error connecting to MongoDB:', err));

// User Schema in  mogo
const userSchema = new mongoose.Schema({
    username: String,
    email: String,
    password: String
});

const User = mongoose.model('User', userSchema);

// Set up views
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));


// Render login form
app.get('/', (req, res) => {
    if (req.session.user) {
        res.redirect('/users');
    } else {
        res.render('login', { error: null });
    }
});



// Handle login form submission
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            // Compare hashed passwords
            const isPasswordValid = await bcrypt.compare(password, existingUser.password);
            if (isPasswordValid) {
                req.session.user = existingUser;
                res.redirect('/users');
            } else {
                res.render('login', { error: 'Invalid email or password' });
            }
        } else {
            res.render('login', { error: 'Invalid email or password' });
        }
    } catch (error) {
        console.error('Error logging in:', error);
        res.status(500).send('Internal Server Error');
    }
});



// Render sign up form
app.get('/sign', (req, res) => {
    res.render('sign', { error: null });
});

// Handle sign up form submission
app.post('/sign', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            res.render('sign', { error: 'Email already exists' });
        } else {
            const HidePassword = await bcrypt.hash(password,10)
            const newUser = new User({ username, email, password:HidePassword });
            await newUser.save();
            // req.session.user = newUser;
            res.redirect('/');
        }
    } catch (error) {
        console.error('Error signing up:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Render users page
app.get('/users', async (req, res) => {
    try {
        if (req.session.user) {
            const userData = await User.findOne({ _id: req.session.user._id });
            if (userData) {
                res.render('users', { user: userData });
                return;
            }
        }
        res.redirect('/');
    } catch (error) {
        console.error('Error fetching user data:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Render edit form
app.get('/users/:userId/edit', async (req, res) => {
    try {
        const userId = req.params.userId;
        const user = await User.findById(userId);
        
        if (!user) {
            return res.status(404).send('User not found');
        }

        res.render('edit', { user: user, error: null });
    } catch (error) {
        console.error('Error rendering edit page:', error);
        res.status(500).send('Internal Server Error');
    }
});




// Handle edit form submission
app.post('/users/edit', async (req, res) => {
    try {
        if (!req.session.user) {
            return res.status(401).send('Unauthorized');
        }

        const { username, email, password } = req.body;
        const userId = req.session.user._id;

        const user = await User.findById(userId);
        
        if (!user) {
            return res.status(404).send('User not found');
        }

        if (user._id.toString() !== userId.toString()) {
            return res.status(401).send('Unauthorized');
        }

        // Update user fields 
        if (username) {
            user.username = username;
        }
        if (email) {
            user.email = email;
        }
        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            user.password = hashedPassword;
        }

        await user.save();

        res.redirect('/users');
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).send('Internal Server Error');
    }
});



// Handle user deletion
app.post('/users/delete', async (req, res) => {
    try {
        if (!req.session.user) {
            return res.status(401).send('Unauthorized');
        }

        const userId = req.body.userId;
        const deletedUser = await User.findByIdAndDelete(userId);

        if (!deletedUser) {
            return res.status(404).send('User not found');
        }

        req.session.destroy();
    
        res.redirect('/');
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).send('Internal Server Error');
    }
});
// Logout route
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
            res.status(500).send('Internal Server Error');
        } else {
            res.redirect('/');
        }
    });
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running at http://localhost:${port}`);
});
