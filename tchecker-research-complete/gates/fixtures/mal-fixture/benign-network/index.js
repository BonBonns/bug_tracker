const https = require("https");
module.exports = function getWeather(city, cb) {
  const url = "https://api.weather.example.com/v1/current?city=" + encodeURIComponent(city);
  https.get(url, cb);
};
