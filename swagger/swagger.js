import swaggerJSDoc from "swagger-jsdoc";

const options = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Local News API",
      version: "1.0.0",
    },
    servers: [
      {
        url: "http://localhost:4000",
      },
    ],
    components: {
      securitySchemes: {
        BearerAuth: {
          // arbitrary name for the security scheme
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT", // optional, arbitrary value for documentation purposes
        },
      },
    },
    security: [{ BearerAuth: [] }], // use the same name as in securitySchemes
  },
  apis: ["./routes/*.js", "./swagger/token.js"], // files containing annotations as above
};

const specs = swaggerJSDoc(options);

export default specs;
