const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const { CleanWebpackPlugin } = require('clean-webpack-plugin');
const webpack = require('webpack');

module.exports = {
  entry: './src/index.tsx',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'bundle.[contenthash].js',
    publicPath: '/',
  },
  resolve: {
    extensions: ['.tsx', '.ts', '.js'],
  },
  module: {
    rules: [
      {
        test: /\.tsx?$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
      {
        test: /\.css$/,
        use: ['style-loader', 'css-loader'],
      },
    ],
  },
  plugins: [
    new CleanWebpackPlugin(),
    new webpack.DefinePlugin({
      __STACKDOG_ENV__: JSON.stringify({
        REACT_APP_API_URL: process.env.REACT_APP_API_URL || '',
        REACT_APP_WS_URL: process.env.REACT_APP_WS_URL || '',
        APP_PORT: process.env.APP_PORT || '',
        REACT_APP_API_PORT: process.env.REACT_APP_API_PORT || '',
      }),
    }),
    new HtmlWebpackPlugin({
      templateContent:
        '<!doctype html><html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>Stackdog</title>' +
        // Written by the container at start-up; absent in dev, where the
        // build-time defaults apply instead.
        '<script src="/config.js"></script>' +
        '</head><body><div id="root"></div></body></html>',
    }),
  ],
  devServer: {
    static: path.resolve(__dirname, 'dist'),
    historyApiFallback: true,
    port: 3000,
  },
};
