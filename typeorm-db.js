var typeorm = require("typeorm");
var EntitySchema = typeorm.EntitySchema;
var secretManager = require("./service/secret-manager");

const Users = require("./entity/Users");

secretManager.accessSecretVersion("nodejs-goof-mysql-password").then((dbPassword) => {
  return typeorm.createConnection({
    name: "mysql",
    type: "mysql",
    host: "localhost",
    port: 3306,
    username: "goof_app",
    password: dbPassword,
    database: "acme",
    synchronize: true,
    logging: true,
    entities: [
      new EntitySchema(Users)
    ]
  });
}).then(() => {
  const dbConnection = typeorm.getConnection("mysql");
  return dbConnection.getRepository("Users");
}).then((repo) => {
  const inserts = [
    repo.insert({
      name: "Liran",
      address: "IL",
      role: "user"
    }),
    repo.insert({
      name: "Simon",
      address: "UK",
      role: "admin"
    })
  ];
  return Promise.all(inserts);
}).catch((err) => {
  console.error("failed connecting and seeding users to the MySQL database");
});
