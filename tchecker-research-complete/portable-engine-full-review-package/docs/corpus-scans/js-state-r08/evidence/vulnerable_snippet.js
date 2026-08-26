
app.post('/auth', async (req, res) => {
    const response = {success: false, message: 'Invalid username/password.'};
    let username = req.body.username;
    let password = req.body.password;
    if (username && password) {
        if (users[username] && users[username] == password) {
            req.session.loggedin = true;
            req.session.username = username;
            response.success = true;
            response.message = 'Login successful!';
        }
    }
    res.send(response);
});
