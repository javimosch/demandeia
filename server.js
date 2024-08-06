const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const path = require("path");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
  dbName: "demandeai",
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Set up EJS as the view engine
app.set("view engine", "ejs");

// Middleware
// Increase the limit to 50mb or adjust as needed
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(__dirname, "public")));

// Routes
const Preset = require("./models/preset");
const User = require("./models/user");


// Middleware to inject global variables for header.ejs
const injectHeaderVariables = (req, res, next) => {
  // Add any variables you want available in header.ejs
  res.locals.user = req.user; // Assuming you're using authentication middleware
  res.locals.siteName = "DemandeAI";
  res.locals.currentPath = req.path;
  // Add any other variables you need globally

  next();
};

// Use the middleware
app.use(injectHeaderVariables);


// Authentication middleware
const auth =
  (required = true) =>
  async (req, res, next) => {
    try {
      const token = req.header("Authorization")?.replace("Bearer ", "");
      if (!token) throw new Error(req.url+": No token provided");

      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findOne({ _id: decoded._id });

      if (!user) {
        throw new Error("User not found");
      }

      req.token = token;
      req.user = user;
      req.isAdmin = user.username === process.env.ADMIN_EMAIL;
      res.locals.user = req.user; // Assuming you're using authentication middleware
      next()
    } catch (error) {
      console.log({ error });
      if (required) {
        // Check if the request is an AJAX request
        if (req.xhr || req.headers.accept.indexOf("json") > -1) {
          console.log('auth fail ajax')
          // For AJAX requests, send a JSON response
          res.status(401).json({ error: "Please authenticate." });
        } else {
          // For non-AJAX requests, redirect to the login page
          console.log('auth fail non-ajax')
          res.redirect("/login");
        }
      } else {
        next();
      }
    }
  };

app.use((req,res,next)=>{
  console.log('REQ',req.url)
  next()
})



app.get("/", async (req, res) => {
    res.render("index")
});

app.get('/api/presets/:id', auth(true), async (req, res) => {
  try {
    let preset;
    if (req.isAdmin) {
      preset = await Preset.findById(req.params.id);
    } else {
      preset = await Preset.findOne({ _id: req.params.id, userId: req.user._id });
    }
    if (!preset) {
      return res.status(404).json({ error: 'Preset not found' });
    }
    res.json(preset);
  } catch (error) {
    console.error('Error fetching preset:', error);
    res.status(500).json({ error: 'An error occurred while fetching the preset' });
  }
});


app.get('/api/presets', auth(true), async (req, res) => {
  try {
    let presets;
    
    // Check if the logged-in user is the admin
    if (req.user.username === process.env.ADMIN_EMAIL) {
      // If admin, fetch all presets
      presets = await Preset.find();
      console.log('admin api/presents')
    } else {
      // If not admin, fetch only the presets owned by the user
      presets = await Preset.find({ userId: req.user._id });
      console.log('non-admin api/presents')
    }
    
    res.json({ presets });
  } catch (error) {
    console.error('Error fetching presets:', error);
    res.status(500).json({ error: 'An error occurred while fetching presets' });
  }
});


app.get("/create", (req, res) => {
  res.render("create",{
    isEditing:false
  });
});

app.post('/api/presets', auth(true), async (req, res) => {
  try {
    const { label, presetJson, formConfig, messageTemplate } = req.body;
    const newPreset = new Preset({
      label,
      presetJson,
      formConfig,
      messageTemplate,
      userId: req.user._id
    });
    const savedPreset = await newPreset.save();
    res.status(201).json(savedPreset);
  } catch (error) {
    console.error('Error creating preset:', error);
    res.status(500).json({ error: 'An error occurred while creating the preset' });
  }
});


app.get('/edit/:id', (req, res) => {
  res.render('create', { isEditing: true, presetId: req.params.id });
});

app.put('/api/user/openai-key', auth(true), async (req, res) => {
  try {
    const { openaiApiKey } = req.body;
    req.user.openaiApiKey = openaiApiKey;
    await req.user.save();
    res.json({ message: 'API key saved successfully' });
  } catch (error) {
    console.error('Error saving API key:', error);
    res.status(500).json({ error: 'An error occurred while saving the API key' });
  }
});


app.put('/api/presets/:id', auth(true), async (req, res) => {
  try {
    const { label, presetJson, formConfig, messageTemplate } = req.body;
    let preset 
    if (req.isAdmin) {
      preset = await Preset.findByIdAndUpdate(
        req.params.id,
        { label, presetJson, formConfig, messageTemplate },
        { new: true }
      );
    } else {
      preset = await Preset.findOneAndUpdate(
        { _id: req.params.id, userId: req.user._id },
        { label, presetJson, formConfig, messageTemplate },
        { new: true }
      );
    }
    if (!preset) {
      return res.status(404).json({ error: 'Preset not found' });
    }
    res.json(preset);
  } catch (error) {
    console.error('Error updating preset:', error);
    res.status(500).json({ error: 'An error occurred while updating the preset' });
  }
});


app.put("/edit/:id", auth(), async (req, res) => {
  const { label, presetJson, formConfig, messageTemplate } = req.body;
  const present = await Preset.findOneAndUpdate(
    { _id: req.params.id, userId: req.user._id },
    { label, presetJson, formConfig, messageTemplate },
    { new: true }
  );
  if (!present) {
    return res.status(404).send("Preset not found");
  }
  res.json(present);
});

app.get("/execute/:id", async (req, res) => {
  const preset = await Preset.findById(req.params.id);
  res.render("execute", { preset: {
    _id:preset._id,
    formConfig:preset.formConfig
  } });
});

app.post('/execute/:id', auth(true), async (req, res) => {
  try {
    const preset = await Preset.findById(req.params.id);
    if (!preset) {
      return res.status(404).json({ error: 'Preset not found' });
    }

    let userApiKey = req.user.oaik;
    if(userApiKey){
      userApiKey= require('atob')(userApiKey)
    }
    if(!userApiKey){
      console.log('no key provided by req, trying user key', req.user.openaiApiKey)
      userApiKey = req.user.openaiApiKey ? req.user.decryptApiKey(req.user.openaiApiKey) : ''
    }
    
    const globalApiKey = process.env.OPENAI_API_KEY;

    if (process.env.DISABLE_GLOBAL_OPENAI_KEY === '1' && !userApiKey) {
      return res.status(400).json({ error: 'OpenAI API key is required' });
    }

    const apiKey = userApiKey || globalApiKey;
    if (!apiKey) {
      return res.status(500).json({ error: 'OpenAI API key is not configured' });
    }

    const OpenAI = require('openai');
    const openai = new OpenAI({ apiKey });

    const formData = req.body;
    const presetJson = JSON.parse(preset.presetJson);

    const messages = [
      {
        role: "system",
        content: [{ type: "text", text: presetJson.messages[0].content[0].text }]
      },
      {
        role: "user",
        content: [{ type: "text", text: preset.messageTemplate }]
      }
    ];

    messages[1].content[0].text = messages[1].content[0].text.replace(/\${(\w+)}/g, (match, key) => formData[key] || match);

    const response = await openai.chat.completions.create({
      model: presetJson.model,
      messages: messages,
      temperature: presetJson.temperature,
      max_tokens: presetJson.max_tokens,
      top_p: presetJson.top_p,
      frequency_penalty: presetJson.frequency_penalty,
      presence_penalty: presetJson.presence_penalty,
    });

    res.json({ result: response.choices[0].message.content });
  } catch (error) {
    console.error('Error executing preset:', error);
    res.status(500).json({ error: 'An error occurred while executing the preset' });
  }
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  try {
    // Check if the user already exists
    let user = await User.findOne({ username: req.body.username });

    if (user) {
      // User already exists, so we'll just log them in
      if (await bcrypt.compare(req.body.password, user.password)) {
        const token = jwt.sign(
          { _id: user._id.toString() },
          process.env.JWT_SECRET
        );
        return res
          .status(200)
          .send({ user, token, message: "Logged in successfully" });
      } else {
        // Username exists but password doesn't match
        return res.status(400).send({ error: "Invalid credentials" });
      }
    } else {
      // User doesn't exist, so create a new one
      user = new User(req.body);
      await user.save();
    }

    // Generate token for the new or existing user
    const token = jwt.sign(
      { _id: user._id.toString() },
      process.env.JWT_SECRET
    );
    res.status(201).send({ user, token, message: "Registered successfully" });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(400).send({ error: "Registration failed" });
  }
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  try {
    const user = await User.findOne({ username: req.body.username });
    if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
      throw new Error("Invalid login credentials");
    }
    const token = jwt.sign(
      { _id: user._id.toString() },
      process.env.JWT_SECRET
    );
    res.send({ user, token });
  } catch (error) {
    res.status(400).send(error);
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
