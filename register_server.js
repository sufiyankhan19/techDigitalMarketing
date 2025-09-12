const express = require('express');
const bodyParser = require('body-parser');
const { Pool }= require('pg');
const app = express();
const port = 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'Digital-Marketing',
  password: 'admin@1234',
  port: 5432,
});

app.post('/signup', async (req, res) => {
    const { fullname, email, company, password } = req.body;
    try {
        await pool.query(
           'INSERT INTO registration (fullname, email, company, password) VALUES ($1, $2, $3, $4)',
           [fullname, email, company, userPassword]);
        res.redirect('/?loggedIn=true');
    } catch (err) {
        console.error('Error inserting data:', err);
        res.status(500).send('Internal Server Error');
        }
});
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});