Python 3.9.6

rest-flask-soc-vv

debug on default port address and port http://127.0.0.1:5000

Debuged by Postman

POSTMAN check examples :

> Register user (its not defended, for work it should be changed):
> http://127.0.0.1:5000/register

> Login user (returns JSON with access token):
> http://127.0.0.1:5000/login

> Add a post (authentification required):
> http://127.0.0.1:5000/post

> Get all posts :
> http://127.0.0.1:5000/posts

> Get info about current user:
> http://127.0.0.1:5000/getinfo

> Get info about current user:
> http://127.0.0.1:5000/getinfo

> Like or dislike selected post:
> http://127.0.0.1:5000/post/1/like
> http://127.0.0.1:5000/post/1/dislike
> 3 states:
> 1 - there is no row
> 2 - there is row and its True (liked)
> 3 - there is row and its False (disliked)
> opposite command for state "there is row" - deletes a row

> Get a statistic for all likes by period:
> http://127.0.0.1:5000/api/analitics/?date_from=2021-12-24&date_to=2021-12-27