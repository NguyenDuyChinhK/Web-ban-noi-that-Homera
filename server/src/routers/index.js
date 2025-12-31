const routesUser = require('./users.routers');

function routes(app) {
    app.post('/api/register', routesUser);
}

module.exports = routes;
