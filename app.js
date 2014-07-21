// example app using inkwell-users
var express = require('express'),
    app = express(),
    mongoose = require('mongoose'),
    mongoUri = 'mongodb://localhost/test',
    port = process.env.PORT || 3000;

mongoose.connect(mongoUri);

require('./users').controller(app);

app.listen(port);