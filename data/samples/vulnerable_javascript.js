// Sample Vulnerable JavaScript Code
// Use this file to test the LLM Code Analyzer

const mysql = require('mysql');
const { exec } = require('child_process');

// Hardcoded credentials - BAD PRACTICE
const API_KEY = "sk-1234567890abcdefghijklmnop";
const DB_PASSWORD = "admin123!@#";
const JWT_SECRET = "super_secret_jwt_key";

// SQL Injection vulnerability
function getUserById(userId) {
    const connection = mysql.createConnection({/* config */});
    // VULNERABLE: String concatenation in SQL query
    const query = "SELECT * FROM users WHERE id = '" + userId + "'";
    connection.query(query, (err, results) => {
        return results;
    });
}

// SQL Injection via template literal
function searchUsers(searchTerm) {
    const connection = mysql.createConnection({/* config */});
    // VULNERABLE: Template literal in SQL
    const query = `SELECT * FROM users WHERE name LIKE '%${searchTerm}%'`;
    connection.query(query, (err, results) => {
        return results;
    });
}

// Command injection vulnerability
function runCommand(userInput) {
    // VULNERABLE: exec with user input
    exec("echo " + userInput, (error, stdout) => {
        console.log(stdout);
    });
}

// Command injection via template literal
function processFile(filename) {
    // VULNERABLE: Command injection
    exec(`cat ${filename}`, (error, stdout) => {
        return stdout;
    });
}

// XSS vulnerability - innerHTML
function displayUserContent(content) {
    // VULNERABLE: innerHTML with user content
    document.getElementById('output').innerHTML = content;
}

// XSS vulnerability - document.write
function writeContent(userHtml) {
    // VULNERABLE: document.write with user content
    document.write(userHtml);
}

// Arbitrary code execution
function calculateExpression(expr) {
    // VULNERABLE: eval with user input
    return eval(expr);
}

// Insecure randomness
function generateToken() {
    // VULNERABLE: Math.random is not cryptographically secure
    return Math.random().toString(36).substring(7);
}

// Prototype pollution potential
function mergeObjects(target, source) {
    for (let key in source) {
        // VULNERABLE: No prototype check
        target[key] = source[key];
    }
    return target;
}

// Regex DoS (ReDoS)
function validateEmail(email) {
    // POTENTIALLY VULNERABLE: Complex regex
    const regex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
    return regex.test(email);
}

module.exports = {
    getUserById,
    searchUsers,
    runCommand,
    displayUserContent,
    calculateExpression,
    generateToken
};
