import express from "express";
import dotenv from 'dotenv'
import cookieParser from "cookie-parser";
import cors from 'cors'
import authRouter from './routes/auth.route.js'
import todoRouter from './routes/todo.route.js'
import path from 'path';
const app = express();

dotenv.config();
const _dirname = path.resolve()

app.use(express.json());
app.use(cookieParser())
app.use(cors({
    origin: 'https://awscognito.onrender.com', // Only allow this domain
    credentials: true, // Enable sending cookies and other credentials
  }))
app.use('/api/user', authRouter)
app.use('/api/todo', todoRouter)


app.use(express.static(path.join(_dirname, '/client/dist')));

app.get('*', (req, res)=>{
  res.sendFile(path.join(_dirname, 'client', 'dist', 'index.html'))
})
app.use((err,req,res,next)=>{
    const statusCode = err.statusCode || 500;
    const message = err.message || 'Internal server error';
    res.status(statusCode).json({
        success : false,
        statusCode,
        message
    })
})
app.listen(3000,()=>{
    console.log("Server running on port 3000")
})

