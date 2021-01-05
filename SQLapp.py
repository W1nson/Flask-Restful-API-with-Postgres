
# This is the file that is invoked to start up a development server. It gets a copy of the app from your package and runs it. 
# This won’t be used in production, but it will see a lot of mileage in development.

from flask import Flask, request, jsonify
from flask_restful import Api, Resource, reqparse, abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
#from flask_mongoengine import MongoEngine
# from flask.ext.bcrypt import Bcrypt
import bcrypt
import datetime


app = Flask(__name__)
api = Api(app)
# bcrypt = Bcrypt(app)

#app.config.from_object('config.DevConfig')

app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:1229@localhost:5432/User_api"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# db = MongoEngine()
# db.init_app(app)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# def getHashedPw (password):
    
#     # always encode the string with utf8 before hasing
#     # hasing need to be done using byte strings
#     # this method will return a string
#     hashed_pw = bcrypt.hashpw (password.encode("utf8"), bcrypt.gensalt())
#     return hashed_pw

# def checkHashedPw (password, hashed_pw):

#     # always encode the string with utf8 before hasing
#     # hasing comparision need to be done using byte strings
#     # this method will return true or false
#     return bcrypt.checkpw (password.encode("utf8"), hashed_pw)



# class UserModel(db.Document):
#     name = db.StringField(required=True)
#     email = db.StringField(required=True)
#     password = db.StringField(required=True)

# def to_integer(dt_time):
#     return 10000*dt_time.year + 100*dt_time.month + dt_time.day


class UsersModel(db.Model):
    __tablename__ = 'user'

    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String)
    email = db.Column(db.String)
    password = db.Column(db.LargeBinary)
    salt = db.Column(db.LargeBinary)


    def __init__(self, username="", email="", password="", salt=""):
        self.username = username
        self.email = email
        self.password = password
        self.salt = salt

    def __repr__(self):
        return f"<Username {self.username}>"





class SetsModel(db.Model):
    __tablename__ = 'sets'

    set_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'))
    word_count = db.Column(db.Integer)
    set_name = db.Column(db.String)
    #store as BIG INT
    date_created = db.Column(db.BigInteger())

    def __init__(self, user_id, word_count, set_name, date_created):
        self.user_id = user_id
        # self.set_id = set_id
        self.word_count = word_count
        self.set_name = set_name
        self.date_created = date_created

    def __repr__(self):
        return f"<set_id {self.set_id}>"

    
class Set_WordModel(db.Model):
    __tablenamme__= 'sets_words'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    set_id = db.Column(db.Integer, db.ForeignKey('sets.set_id'))
    # word_id = db.Column(db.Integer, db.ForeignKey('words.word_id'))

    pre_sentence = db.Column(db.String)
    post_sentence = db.Column(db.String)
    correct_word = db.Column(db.String)

    def __init__(self, set_id, pre_sentence, post_sentence, correct_word):
        self.set_id = set_id
        # self.word_id = word_id
        self.pre_sentence = pre_sentence
        self.post_sentence = post_sentence
        self.correct_word = correct_word

    def __repr__(self):
        return f"<set_id {self.set_id}>"
        # return {
        #     "set_id" : self.set_id,
        #     "pre" : self.pre_sentence, 
        #     "correct" : self.correct_word,
        #     "post" : self.post_sentence
        # }





class Register(Resource):
    #get from the server
    
    # def get(self):
    #     if request.is_json:
    #         data = request.get_json()
    #         username_check = UsersModel.query.filter(UsersModel.username == data["username"]).first()
    #         email_check = UsersModel.query.filter(UsersModel.email == data["email"]).first()
    #         if username_check:
    #             abort(402, message="Username Already Exist")
    #         if email_check:
    #             abort(403, message="Email Already Exist") 
    #         return {"message" : True}
    #     return {"message" : "wrong format"}
    #     #check if the User already exits by searching through the database 

    
    #create new data in the server
    def post(self):
        #inserting the new data into database 
        if request.is_json:
            data = request.get_json()
            username_check = UsersModel.query.filter(UsersModel.username == data["username"]).first()
            email_check = UsersModel.query.filter(UsersModel.email == data["email"]).first()
            if username_check:
                abort(400, message="Username Already Exist")
            if email_check:
                abort(400, message="Email Already Exist") 

            user_salt = bcrypt.gensalt()
            hashed_pw = bcrypt.hashpw (data["password"].encode("utf8"), user_salt)


            new_user = UsersModel(username=data['username'], email=data['email'], password=hashed_pw, salt=user_salt)
            # print(new_user.password)
            db.session.add(new_user)
            db.session.commit()
            return {"message": f"User {new_user.username} has been created successfully."}
        else:
            return {"message" : "wrong format"}
        
    def delete(self):
        if request.is_json:
            data = request.get_json() 
            username_check = UsersModel.query.filter(UsersModel.username == data["username"]).first()
            if not username_check:
                abort(401, message="User not exist")
            
            db.session.delete(username_check)
            db.session.commit()
            return {"message": "user deleted"}, 202
        else:
            return {"message" : "wrong format"}
    
#     #update data in the server
#     # @marshal_with(resource_fields)
#     def patch(self):
#         args = input_put_args.parse_args()
#         #changing email with confirmed name and password
#         user = UserModel.objects(name=args["name"], password=args["password"]).first()
#         if not user: 
#             return {"message": "failed"}, 405
#         else:
#             user.update(email=args["email"])
#             return {"message": "email updated"}, 203

    
#         # #changing password with confirmed name and email 
#         # if args["name"] and args["email"]:
#         #     user = UserModel.objects(name=args["name"], email=args["email"]).first()
#         #     user.update(password=args["password"])
#         #     return {"message": "password updated"}, 204
#         # if args["email"] and args["password"]:
#         #     user = UserModel.objects(email=args["email"], password=args["password"]).first()
#         #     user.update(name=args["name"])
#         #     return {"message": "name updated"}, 205

#         # return {"message": "failed"}, 206

        
        



class LogIn(Resource):
    
    def post(self):
        if request.is_json:
            data = request.get_json()
            username_check = UsersModel.query.filter(UsersModel.username == data["username"]).first()
            email_check = UsersModel.query.filter(UsersModel.email == data["email"]).first()
            
            user = email_check
            pw = data["password"]
            if username_check:
                user = username_check
                hashed_pw = bcrypt.hashpw (pw.encode("utf8"), username_check.salt)
            else:
                hashed_pw = bcrypt.hashpw (pw.encode("utf8"), email_check.salt)

            # print(getHashedPw(pw))
            # print()
            # print(username_check.password)
            password_check = False
            # if checkHashedPw(pw, username_check.password) or checkHashedPw(pw, email_check.password):
            #     password_check = True
            if hashed_pw == username_check.password or hashed_pw == email_check.password:
                password_check = True

            if not username_check:
                abort(403, message="username wrong")
            if not email_check:
                abort(403, message="email wrong")
            if not password_check: 
                abort(403, message="password wrong")
            

            return {"user_id" : user.user_id}, 200
        else:
            return {"message" : "wrong format"} 



class CreateSets(Resource):
    def post(self, userid):
        
        if request.is_json:
            data = request.get_json()
            
            new_set = SetsModel(user_id=userid, word_count=data["word_count"], set_name=data["set_name"], date_created=data["data_created"])
            # print(new_user.password)
            db.session.add(new_set)
            db.session.commit()
        
            return { "set_id" : new_set.set_id}, 200
        else: 
            return { "message" : "wrong format"}, 400

class DeleteSets(Resource):
    def delete(self, setid):
        set_find = SetsModel.query.filter_by(set_id=setid).first()
        if not set_find:
            abort(401, message="Set not exist")

        db.session.delete(set_find)      
        db.session.commit()
        return {"message": "Set deleted"}, 202



class CreateCards(Resource):
    def post(self, setid):
        if request.is_json:
            data = request.get_json()
            newCard = Set_WordModel(set_id=setid, pre_sentence=data["pre"], post_sentence=data["post"], correct_word=data["correct"])
            db.session.add(newCard)
            db.session.commit()
            return {"message": "card inserted"}, 200

class getCards(Resource):
    def get(self, setid):
        cards = Set_WordModel.query.filter(Set_WordModel.set_id == setid).all()
        # if(set_find)
    
        results = [
            {
            "set_id" : card.set_id,
            "pre" : card.pre_sentence, 
            "correct" : card.correct_word,
            "post" : card.post_sentence
        } for card in cards]
        return results, 200

class deleteCards(Resource): 
    def delete(self, word_id):
        card = Set_WordModel.query.filter(Set_WordModel.id == word_id).first()
        if not card:
            abort(401, message="Set not exist")

        db.session.delete(card)      
        db.session.commit()
        return {"message": "card deleted"}, 200


api.add_resource(Register, "/api/register")
api.add_resource(LogIn, "/api/login")
api.add_resource(CreateSets, "/api/CreateSets/<int:userid>")
api.add_resource(DeleteSets, "/api/deleteSets/<int:setid>")
api.add_resource(CreateCards, "/api/CreateCards/<int:setid>")
api.add_resource(getCards, "/api/getCards/<int:setid>")
api.add_resource(deleteCards, "/api/deleteCards/<int:word_id>")



if __name__ == "__main__":
    app.run(debug=True)