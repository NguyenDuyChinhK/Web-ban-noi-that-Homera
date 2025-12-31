const routesUser = require('./users.routes');

function routes(app) {
    app.post('/api/register', routesUser);
    app.post('/api/login', routesUser);
}

module.exports = routes;
