var path = require('path');
var webpack = require('webpack');
const UglifyJsPlugin = require('uglifyjs-webpack-plugin');

module.exports = {
		entry: {
      admin: './src/admin.js',
      login: './src/login.js',
      profile: './src/profile.js'
    },
		output: {
				path: path.resolve(__dirname, 'output'),
				filename: '[name].js',
				libraryTarget: 'umd'
		},

		module: {
				loaders: [
						{
								test: /\.js$/,
								exclude: /(node_modules|bower_components|build)/,
								use: {
										loader: 'babel-loader',
										options: {
												presets: ['env']
										}
								}
						},
						{
								test: /\.css$/,
								loader: 'style-loader!css-loader'
						}
				]
		},

		 plugins: [
				new webpack.DefinePlugin({
						"process.env": { 
								NODE_ENV: JSON.stringify("production") 
						}
				}),
				new UglifyJsPlugin({
					test: /\.js($|\?)/i,
					sourceMap: true,
					uglifyOptions: {
						mangle: {
							keep_fnames: true
						},
						compress: {
							warnings: false
						},
						output: {
							beautify: false
						}
					}
				})
		]
}
