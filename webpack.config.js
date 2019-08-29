const path = require('path');

module.exports = {
  mode: 'development',
  entry: './src/petunia.js',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'main.js',
    library: "Petunia",
    libraryTarget: "umd"
  }
};
