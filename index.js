
// Libraries
const {Neo4jGraphQL} = require("@neo4j/graphql");
const {OGM} = require("@neo4j/graphql-ogm");
const {Neo4jGraphQLAuthJWTPlugin} = require("@neo4j/graphql-plugin-auth");
const { startStandaloneServer } = require('@apollo/server/standalone');
const { ApolloServer } = require('@apollo/server');
const neo4j = require("neo4j-driver");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

// Load .env File Config
require('dotenv').config()

// JWT Generator with User func
function createJWT(data) {
    return new Promise((resolve, reject) => {
        jwt.sign(data, process.env.JWT_SECRET, (err, token) => {
            if (err) {
                return reject(err);
            }
            return resolve(token);
        });
    });
}

// Check Password and validate func
function comparePassword(plainText, hash) {
    return new Promise((resolve, reject) => {
        bcrypt.compare(plainText, hash, (err, result) => {
            if (err) {
                return reject(err);
            }
            return resolve(result);
        });
    });
}
// SignUp Resolver
const signUp = async (_source, { username, password }) => {
    const [existing] = await User.find({
        where: {
            username,
        },
    });

    if (existing) {
        throw new Error(`User with username ${username} already exists!`);
    }

    const { users } = await User.create({
        input: [
            {
                username,
                password,
            }
        ]
    });

    return createJWT({ sub: users[0].id });
};
// signIn Resolver
const signIn = async (_source, { username, password }) => {
    const [user] = await User.find({
        where: {
            username,
        },
    });

    if (!user) {
        throw new Error(`User with username ${username} not found!`);
    }

    const correctPassword = await comparePassword(password, user.password);

    if (!correctPassword) {
        throw new Error(`Incorrect password for user with username ${username}!`);
    }

    return createJWT({ sub: user.id });
};


// initialize Neo44J from .env config
const driver = neo4j.driver(
    process.env.DB_URI,
    neo4j.auth.basic(process.env.DB_USERNAME, process.env.DB_PASSWORD)
);

// Define Types
const typeDefs = `#graphql
    type Todo {
        id: ID @id
        title: String!
        author: User! @relationship(type: "AUTHORED", direction: IN)
    }
    
    type User {
        id: ID @id
        username: String!
        password: String! @private
    }
    
    extend type User @auth(
        rules: [
            {
                operations: [READ],
                allow: { id: "$jwt.sub" }
            }
        ]
    )
    extend type Todo
        @auth(
            rules: [
                {
                    operations: [UPDATE,CREATE],
                    allow: { OR: [{ author: { id: "$jwt.sub" } }] }
                }
            ]
        )
    
    type Mutation {
        signUp(username: String!, password: String!): String! ### JWT
        signIn(username: String!, password: String!): String! ### JWT
    }
`;

const ogm = new OGM({ typeDefs, driver });
const User = ogm.model("User");

// Create signUp and SignIn Resolvers
const resolvers = {
    Mutation: {
        signUp,
        signIn
    },
};

const neoSchema = new Neo4jGraphQL({
    typeDefs,
    driver,
    resolvers,
    plugins: {
        auth: new Neo4jGraphQLAuthJWTPlugin({
            secret: process.env.JWT_SECRET
        })
    }
});

Promise.all([neoSchema.getSchema(), ogm.init()]).then(([schema]) => {
    const server = new ApolloServer({
        schema,
    });

    startStandaloneServer(server, {
        context: async ({ req }) => ({ req }),
    }).then(({ url }) =>  {
        console.log(`🚀 Server ready at ${url}`);
    });
});