import express from 'express'
import { addTodo, deleteTodo, getTodos, updateTodo } from '../controllers/todo.controller.js';
import { verifyUser } from '../utils/verifyUser.js';

const router = express.Router();

router.post("/add/:userId", verifyUser,addTodo)
router.get("/get/:userId", verifyUser,getTodos)
router.put("/update/:userId/:todoId", verifyUser,updateTodo)
router.delete("/delete/:userId/:todoId", verifyUser,deleteTodo)
export default router;