const mongoose=require('mongoose')

mongoose.set('strictQuery', true);

const DB=process.env.DATABASE;

mongoose.connect(DB).then(() =>{
    console.log('connection successful');
}).catch((err)=>console.log(err));