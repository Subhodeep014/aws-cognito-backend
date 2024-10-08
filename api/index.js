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
app.use(cors())
app.use('/api/user', authRouter)
app.use('/api/todo', todoRouter)


// app.use(express.static(path.join(_dirname, '/client/dist')));

// app.get('*', (req, res)=>{
//   res.sendFile(path.join(_dirname, 'client', 'dist', 'index.html'))
// })
app.use((err,req,res,next)=>{
    const statusCode = err.statusCode || 500;
    const message = err.message || 'Internal server error';
    res.status(statusCode).json({
        success : false,
        statusCode,
        message
    })
})
const PORT = process.env.PORT || 8080
app.listen(PORT,()=>{
    console.log(`Server running on port ${PORT}`)
})

