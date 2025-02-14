var path = require('path');

module.exports = {
		entry: {
      admin: './src/admin.js',
      login: './src/login.js',
      profile: './src/profile.js'
    },
		devtool: 'inline-source-map',
		output: {
				path: path.resolve(__dirname),
				filename: '[name].js',
				libraryTarget: 'umd'
		},

		devServer: {
				contentBase: path.resolve(__dirname),
				compress: true,
				port: 3000,
				host: 'localhost',
				open: true
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
		}
}
