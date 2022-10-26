import os
import time
import json

from flask import Flask, request
from flask_restful import Resource, Api
from pycti import OpenCTIApiClient

from werkzeug.utils import secure_filename
from functools import wraps

from pycti import OpenCTIApiClient

  
app = Flask(__name__)

api = Api(app)

API_URL = "http://localhost:4000"

def getToken():
    try:
        headerParam = request.headers.get('authorization')
        token = headerParam.split(" ")
        if token[0] != "Bearer":
            return False
    except:
        return False
    return token[1]

def auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # TODO
        token = getToken()
        if not token:
            return {'message': "unauthorized!"}, 401  
        try:
            opencti_api_client = OpenCTIApiClient(API_URL, token)
        except Exception as exp:
            return {'message': "unauthorized!"}, 401  
        return f(*args, **kwargs)
    return decorated_function

class PushData(Resource):

    @auth_required
    def post(self):
        try:
            data = request.get_json()     
            if type(data) != list:
                return {'message': 'data is not list format!'}, 400
            path = os.path.join("/", getToken())
            print (path)
            if not os.path.exists(path):
                f = open(path, "w+")
                f.close()
            dataFilePointer = open(path)
            dataFile = dataFilePointer.read()
            dataFilePointer.close()
            try:
                listData = json.loads(dataFile)
            except Exception as exp:
                print ("Can not read data file")
                listData = []
            listData.extend(data)
            dataFilePointer = open(os.path.join("/", getToken()), "w")
            dataFilePointer.write(json.dumps(listData))
            dataFilePointer.close()
            return {'message': "suceess!"}, 201
        except Exception as exp:
            return {'message': "failed!"}, 500 


class PushFileData(Resource):

    @auth_required
    def post(self):
        try:
            path = os.path.join("/", getToken())
            fileUpload = request.files['file-data']
            uniqueName = str(time.time()) + secure_filename(fileUpload.filename)
            fileUpload.save(os.path.join("/", uniqueName))

            dataFilePointer = open(os.path.join("/", uniqueName))
            data = dataFilePointer.read()
            dataFilePointer.close()
            try:
                reqListData = json.loads(data)
            except Exception as exp:
                print ("Can not read data")
                return {'message': "failed!"}, 400 
            if type(reqListData) != list:
                return {'message': 'data is not list format!'}, 400

            if not os.path.exists(path):
                f = open(path, "w+")
                f.close()
            dataFilePointer = open(path)
            dataFile = dataFilePointer.read()
            dataFilePointer.close()
            try:
                listData = json.loads(dataFile)
            except Exception as exp:
                print ("Can not read data file")
                listData = []

            listData.extend(reqListData)

            dataFilePointer = open(path, "w")
            dataFilePointer.write(json.dumps(listData))
            dataFilePointer.close()

            return {'message': "suceess!"}, 201 
        except Exception as exp:
            return {'message': "failed!"}, 500 

class GetData(Resource):
    # @auth_required
    def get(self):

        return {'message': "suceess!"}, 201 

class GetFileData(Resource):

    def get(self):
        return {'message': "suceess!"}, 201 

  
api.add_resource(PushData, '/push-data')  
api.add_resource(PushFileData, '/push-file-data')
api.add_resource(GetData, '/get-data')
api.add_resource(GetFileData, '/get-file-stix2-data')
  
if __name__ == '__main__':
    app.run(host="0.0.0.0", port="5000", debug = True)