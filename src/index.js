import "dotenv/config";
import app from "./app.js";
import connectDB from "./db/index.js";

connectDB()
  .then(() => {
    app.listen(() => {
      console.log(`Server is listening on port: ${process.env.PORT}`);
    });
  })
  .catch((error) => {
    console.log(error);
  });
