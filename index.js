require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

const http = require('http'); // <-- ✅ Required for socket.io
const { Server } = require('socket.io');

const app = express();
const port = process.env.PORT || 5000;




const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*", 
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors());
app.use(express.json());

// ✅ SOCKET.IO logic







// MongoDB URI
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.v16vj.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// Main DB logic
async function run() {
  try {
    await client.connect();

    const database = client.db('setuDB');
    const usersCollection = database.collection('users');
    const profileCollection = database.collection('profile-data');
    const jobsCollection = database.collection('jobs');
    const applyJobsCollection = database.collection('applyJobs');
    const chatMessagesCollection = database.collection('chatMessages');
    const userSockets = {}; // Map identity -> socket.id

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  // Register user identity (e.g., email or username)
  socket.on('register', (identity) => {
    userSockets[identity] = socket.id;
    console.log(`Registered user: ${identity} -> ${socket.id}`);
  });

  // Handle incoming message and broadcast to all clients
const sensitiveInfoRegex = {
  phone: /(\+?\d{1,4}[\s-]?)?(\(?\d{3}\)?[\s-]?)?[\d\s-]{7,}/g,  // phone-like numbers (loose)
  email: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i,             // emails
  telegram: /telegram\.me\/[a-zA-Z0-9_]+/i,                       // telegram links
  whatsapp: /(\+?\d{1,4}[\s-]?)?(\(?\d{3}\)?[\s-]?)?[\d\s-]{7,}/i // same as phone for whatsapp
};

socket.on('send_message', async (data) => {
  console.log('Message received:', data);
  
  const { content, sender } = data;

  // Check for sensitive info
  const containsSensitiveInfo =
    sensitiveInfoRegex.phone.test(content) ||
    sensitiveInfoRegex.email.test(content) ||
    sensitiveInfoRegex.telegram.test(content) ||
    sensitiveInfoRegex.whatsapp.test(content);

  if (containsSensitiveInfo) {
    console.log(`Sensitive info detected in message from ${sender}. Removing user...`);

    // Remove user from database (ban)
    try {
      await usersCollection.deleteOne({ email: sender });
      // Optionally emit event to notify client or disconnect socket
      socket.emit('banned', { reason: 'You sent prohibited information.' });
      socket.disconnect(true);
    } catch (err) {
      console.error('Error removing user:', err);
    }

    return; // Do NOT save or broadcast the message
  }

  try {
    await chatMessagesCollection.insertOne({
      ...data,
      timestamp: new Date(),
    });
    io.emit('receive_message', data); // broadcast to all clients
  } catch (error) {
    console.error('Error saving message:', error);
  }
});



  // Cleanup on disconnect
  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
    for (const identity in userSockets) {
      if (userSockets[identity] === socket.id) {
        delete userSockets[identity];
        break;
      }
    }
  });
});

app.get('/chat/messages', async (req, res) => {
  try {
    const messages = await chatMessagesCollection.find({}).sort({ timestamp: 1 }).toArray();
    res.send(messages);
  } catch (error) {
    console.error('Failed to get chat messages:', error);
    res.status(500).send({ error: 'Failed to fetch chat messages' });
  }
});


    app.post('/jwt',async(req,res)=>{
      const user=req.body;
      const token= jwt.sign(user,process.env.ACCESS_TOKEN_SECRET,{expiresIn:'1h'});
      res.send({token});
    })
   const verifyToken=(req,res,next)=>{
      if(!req.headers.authorization){
        return res.status(401).send({message:'unauthorized access'})
      }
      const token=req.headers.authorization.split(' ')[1];
      jwt.verify(token,process.env.ACCESS_TOKEN_SECRET,(err,decoded)=>{
        if(err){
          return res.status(401).send({ message: 'unauthorized access' })
        }
        req.decoded=decoded;
        next()
      })
    }




app.get('/chat/access/:email', async (req, res) => {
  const { email } = req.params;

  try {
    // Look for any accepted application where the user is either poster or applicant
    const acceptedApplication = await applyJobsCollection.findOne({
      status: 'accepted',
      $or: [
        { applicantEmail: email },
        { jobPosterEmail: email }
      ]
    });

    if (!acceptedApplication) {
      return res.status(403).send({ access: false, message: 'No accepted chat found for this user' });
    }

    // Return jobId for frontend to use in message loading
    return res.send({ access: true, jobId: acceptedApplication.jobId });
  } catch (error) {
    console.error('Chat access check failed:', error);
    return res.status(500).send({ access: false, message: 'Internal server error' });
  }
});



// Mention Users Endpoint
app.get('/mention-users', async (req, res) => {
  try {
    const users = await profileCollection.find().toArray();
    const mentionList = users.map(user => ({
      id: user.Email,
      display: `${user.firstName} ${user.lastName}`,
    }));
    res.json(mentionList);
  } catch (error) {
    console.error("Error fetching mention users:", error);
    res.status(500).send({ error: 'Failed to fetch users for mentions' });
  }
});






    // ✅ POST new user if not exists
    app.post('/user/:email', async (req, res) => {
      const email = req.params.email;
      const userData = req.body;
      const query = { Email: email }; 
      const exist = await usersCollection.findOne(query);

      if (exist) {
        return res.send({ message: 'User already exists', insertedId: null });
      }

      const result = await usersCollection.insertOne({
        ...userData,
        Email: email,
        role: 'user',
        timestamp: new Date(),
      });
      res.send(result);
    });

    // ✅ Create profile
  app.post('/profile-data', async (req, res) => {
  try {
    const newProfile = req.body;
    const result = await profileCollection.insertOne(newProfile);
    res.send(result);
  } catch (err) {
    console.error("Insert error:", err);
    res.status(500).send({ error: "Failed to save profile" });
  }
});

    // ✅ Update profile
 app.patch('/profile-data/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const updatedProfile = req.body;
    const result = await profileCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updatedProfile }
    );
    res.send(result);
  } catch (err) {
    console.error("Update error:", err);
    res.status(500).send({ error: "Failed to update profile" });
  }
});

    // ✅ Get profile data by email
    app.get('/profile-data', async (req, res) => {
      const email = req.query.email;
      if (!email) {
        return res.status(400).send({ error: "Email is required" });
      }

      const query = { Email: email }; // ✅ Capital E as used in insert
      const userDetails = await profileCollection.findOne(query);

      if (!userDetails) {
        return res.status(404).send({ message: "User not found" });
      }

      res.send(userDetails);
    });

    app.get('/user', async (req, res) => {
      const email = req.query.email;
      if (!email) {
        return res.status(400).send({ error: "Email is required" });
      }

      const query = { Email: email };
      const userDetails = await usersCollection.findOne(query);

      if (!userDetails) {
        return res.status(404).send({ message: "User not found" });
      }

      res.send(userDetails);
    });

   
    app.get('/user/admin/:email', async (req, res) => {
      const email = req.params.email;
     
      const query = { Email: email };
      const user = await profileCollection.findOne(query);
      const admin = user?.role === 'admin';
      res.send({ admin });
    });
  
app.get('/jobs', async (req, res) => {
  try {
    const status = req.query.status; // e.g., 'accept' or 'pending'
    const query = status ? { status } : {};
    const jobs = await jobsCollection.find(query).sort({ timestamp: -1 }).toArray();
    res.send(jobs);
  } catch (error) {
    res.status(500).send({ error: "Failed to fetch jobs" });
  }
});

app.patch('/jobs/:id', async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  try {
    const result = await jobsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { status } }
    );
    res.send(result);
  } catch (error) {
    res.status(500).send({ error: 'Failed to update job status' });
  }
});

// DELETE job
app.delete('/jobs/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const result = await jobsCollection.deleteOne({ _id: new ObjectId(id) });
    res.send(result);
  } catch (error) {
    res.status(500).send({ error: 'Failed to delete job' });
  }
});


app.post('/jobs', async (req, res) => {
  try {
    const job = req.body;
    job.status = "pending";          
    job.timestamp = new Date();      


    const result = await jobsCollection.insertOne(job);

    res.status(201).send(result);
  } catch (error) {
    console.error("Error posting job:", error);
    res.status(500).send({ error: "Failed to post job" });
  }
});


    
    app.get('/user/moderator/:email', async (req, res) => {
      const email = req.params.email;
      const query = { Email: email };
      const user = await usersCollection.findOne(query);
      const moderator = user?.role === 'moderator';
      res.send({ moderator });
    });


// Apply for a job
app.post('/apply-jobs', async (req, res) => {
  try {
    const application = req.body;
    application.status = 'pending';
    application.appliedAt = new Date();

    const result = await applyJobsCollection.insertOne(application);
    res.status(201).send(result);
  } catch (error) {
    console.error("Error applying for job:", error);
    res.status(500).send({ error: "Failed to apply for job" });
  }
});
app.get('/apply-jobs', async (req, res) => {
  const posterEmail = req.query.posterEmail;

  if (!posterEmail) {
    return res.status(400).send({ error: 'posterEmail is required' });
  }

  try {
    // Step 1: Find jobs posted by the current user
    const postedJobs = await jobsCollection.find({ Email: posterEmail }).toArray();
    const jobIds = postedJobs.map(job => job._id.toString());

    // Step 2: Find applications to those jobs
    const applications = await applyJobsCollection
      .find({ jobId: { $in: jobIds } })
      .toArray();

    res.send(applications);
  } catch (error) {
    console.error('Error fetching applications:', error);
    res.status(500).send({ error: 'Failed to fetch applications' });
  }
});


    app.patch('/accept-application', async (req, res) => {
      const { applicantEmail, jobId } = req.body;

      if (!applicantEmail || !jobId) {
        return res.status(400).send({ error: 'applicantEmail and jobId are required' });
      }

      try {
        const result = await applyJobsCollection.updateOne(
          { applicantEmail, jobId },
          { $set: { status: "accepted" } }
        );

        if (result.modifiedCount === 0) {
          return res.status(404).send({ error: 'Application not found or already accepted' });
        }

        res.send({ message: 'Application accepted successfully', modifiedCount: result.modifiedCount });
      } catch (error) {
        console.error('Error accepting application:', error);
        res.status(500).send({ error: 'Internal server error' });
      }
    });


    await client.db("admin").command({ ping: 1 });
    console.log("✅ Connected to MongoDB successfully");
  } catch (err) {
    console.error("❌ MongoDB connection failed:", err);
  }
}



app.get('/view-profile/:email', async (req, res) => {
  const email = req.params.email;

  if (!email) {
    return res.status(400).json({ error: "Email parameter is required" });
  }

  try {
    const query = { Email: email }; 
    const profile = await profileCollection.findOne(query);

    if (!profile) {
      return res.status(404).json({ message: "Profile not found" });
    }

    res.send(profile);
  } catch (error) {
    console.error("Error fetching profile:", error);
    res.status(500).json({ error: "Server error while fetching profile" });
  }
});


run().catch(console.dir);

// Root endpoint
app.get('/', (req, res) => {
  res.send('Setu Server is Running');
});

server.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
});
