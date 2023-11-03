const path = require('path')
const webpack = require('webpack')

module.exports = {
  stats: { errorDetails: true },
  mode: 'none',
  optimization: {
    minimize: false
  },
  target: 'webworker',
  output: {
    path: path.join(process.cwd(), 'bin'),
    filename: 'index.js',
    libraryTarget: 'this'
  },
  module: {
    rules: []
  },
  resolve: {
    fallback: {
      buffer: require.resolve('buffer/')
    }
  },
  plugins: [
    new webpack.ProvidePlugin({
      Buffer: ['buffer', 'Buffer']
    })
  ],
  externals: [
    ({ request }, callback) => {
      if (/^fastly:.*$/.test(request)) {
        return callback(null, 'commonjs ' + request)
      }
      callback()
    }
  ]
}
