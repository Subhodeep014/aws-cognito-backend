import { errorHandler } from '../utils/error.js';
import { PutCommand, QueryCommand, UpdateCommand, DeleteCommand } from '@aws-sdk/lib-dynamodb';
import dynamoClient  from '../config/dynamoClient.js'; // Assuming you've set up a dynamoClient

export const addTodo = async(req, res, next)=>{
    const {todo} = req.body;
    const userId = req.user.userId
    if(userId!==req.params.userId){
        return next(errorHandler(403, 'Unauthorized action'))
    }
    
    try {
        const todoItem = {
            userId,
            todoId : `todo_${Date.now()}`,
            todo,
            createdAt: Date.now(),
            completed : false    
        }

        const command = new PutCommand({
            TableName : process.env.DYNAMODB_TODO_TABLE,
            Item : todoItem
        })
        await dynamoClient.send(command);

        return res.status(200).json({
            message: 'Todo added sucessfully',
            todo : todoItem,
        })
    } catch (error) {
        console.log('Error adding to-do:', error);
        return next(errorHandler(500, 'Failed to add todo'));
    } 
}
export const getTodos = async(req,res, next)=>{
    const userId = req.user.userId;
    if(userId!==req.params.userId){
        return next(errorHandler(403,'Unauthorized action'));
    }
    try {
        const command = new QueryCommand({
            TableName : process.env.DYNAMODB_TODO_TABLE,
            KeyConditionExpression : 'userId= :userId',
            ExpressionAttributeValues : {
                ':userId' : userId
            }
        })
        const result = await dynamoClient.send(command);
        return res.status(200).json({
            message : "Todos retrived successfully",
            todos : result.Items,
        })
    } catch (error) {
        console.error('Error in fetching todos:', error);
        return next(errorHandler(500,'Failed to fetch todos'));
    }
}

export const updateTodo = async (req, res, next) => {
    const { todoId } = req.params; // Assume the todoId is passed in the request URL
    const { todo, completed } = req.body;     // The updated to-do content
    const userId = req.user.userId; // Extract the userId from the authenticated user
  
    if (userId !== req.params.userId) {
      return next(errorHandler(403, 'Unauthorized action'));
    }
  
    try {
      const command = new UpdateCommand({
        TableName: process.env.DYNAMODB_TODO_TABLE,
        Key: {
          userId,   // Partition key (your primary key)
          todoId,   // Sort key (if applicable)
        },
        UpdateExpression: 'set #todo = :todo, #completed = :completed', // Update the 'todo' field
        ExpressionAttributeNames: {
            '#todo': 'todo',  // Alias for attribute names (since 'todo' might be a reserved keyword)
            '#completed': 'completed',
        },
        ExpressionAttributeValues: {
            ':todo': todo,    // The updated todo value
            ':completed': completed,
        },
        ReturnValues: 'ALL_NEW', // Return the updated item after the operation
      });
  
      const result = await dynamoClient.send(command);
  
      return res.status(200).json({
        message: 'Todo updated successfully',
        todo: result.Attributes,  // The updated to-do item
      });
    } catch (error) {
      console.error('Error updating to-do:', error);
      return next(errorHandler(500, 'Failed to update todo'));
    }
};

export const deleteTodo = async(req,res)=>{
    const userId = req.user.userId;
    const {todoId} = req.params;
    if(userId!==req.params.userId){
        return next(errorHandler(403, 'Unauthorized action'));
    }
    try {
        const command = new DeleteCommand({
            TableName : process.env.DYNAMODB_TODO_TABLE,
            Key: {
                userId, todoId
            }
        })
        await dynamoClient.send(command);
        return  res.status(200).json({
            message: 'Todo deleted successfully'
        })
    } catch (error) {
        console.error('Error in deleting todo',error);
        return next(errorHandler(500, 'Failed to delete todo'));
    }
}