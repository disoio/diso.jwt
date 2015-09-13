Assert = require('assert')
Sinon  = require('sinon')

JWT = require('../index')

class User
  constructor : (@_id)->

  id : ()->
    @_id

  @findByToken : (args)->
    {token, id, callback} = args
    user = new @(id)
    callback(null, user)

jwt = new JWT(
  secret : 'bork'
  User   : User
)

Sinon.spy(User, 'findByToken')

module.exports = {
  "JWT" : {
    "should encode and decode" : ()->
      id = 100
      user = new User(id)

      encoded = jwt.encode(user)
      Assert.equal(encoded.user._id, id)

      decoded = jwt.decode(encoded.token)
      Assert.equal(decoded, id)

    "should handleMessage properly" : (done)->

      id = 101
      user = new User(id)
      message = {
        token : jwt.encode(user).token
      }

      jwt.handleMessage(
        message  : message
        callback : (error)->
          Assert.equal(error, null)
          Assert.equal(User.findByToken.callCount, 1)
          Assert.equal(message.user._id, id)
          done()
      )

    "should function as middleware" : (done)->
      id = 10111
      user = new User(id)
      token = jwt.encode(user).token

      request = {
        url : "http://example.com?token=#{token}"
      }
      response = {}

      jwt.handle(request, response, (error)->
        Assert.equal(error, null)
        Assert.equal(User.findByToken.callCount, 2)
        Assert.equal(request.token, token)
        Assert.equal(request.user._id, id)
        done()
      )
  }
}
