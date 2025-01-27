import os
import time
import json
import yaml
import dateutil
import re

from flask import Flask, request, send_file
from flask_restful import Resource, Api
from pycti import OpenCTIApiClient

from werkzeug.utils import secure_filename
from functools import wraps

from pycti import OpenCTIApiClient

  
app = Flask(__name__)

api = Api(app)

config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
config = (
    yaml.load(open(config_file_path), Loader=yaml.FullLoader)
    if os.path.isfile(config_file_path)
    else {}
)

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
        token = getToken()
        if not token:
            return {'message': "unauthorized!"}, 401  
        try:
            opencti_api_client = OpenCTIApiClient(config['opencti']['url'], token)
        except Exception as exp:
            raise (exp)
            return {'message': "unauthorized!"}, 401  
        return f(*args, **kwargs)
    return decorated_function

DATETIME_ISO8601 = re.compile(
    r'^([0-9]{4})' r'-' r'([0-9]{1,2})' r'-' r'([0-9]{1,2})' # date
    r'([T\s][0-9]{1,2}:[0-9]{1,2}:?[0-9]{1,2}(\.[0-9]{1,6})?)?' # time
    r'((\+[0-9]{2}:[0-9]{2})| UTC| utc)?' # zone
)
# check datetime
def datetime_iso(string):
    """ verify rule
    Mandatory is: 'yyyy-(m)m-(d)dT(h)h:(m)m'        
    """
    string = string.strip()
    return bool(re.fullmatch(DATETIME_ISO8601, string))

class PushData(Resource):

    @auth_required
    def post(self):
        try:
            data = request.get_json()     
            if type(data) != list:
                return {'message': 'data error!'}, 400
            path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", getToken())
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
            dataFilePointer = open(path, "w")
            dataFilePointer.write(json.dumps(listData))
            dataFilePointer.close()
            return {'message': "suceess!"}, 201
        except Exception as exp:
            return {'message': "failed!"}, 500 


class PushFileData(Resource):

    @auth_required
    def post(self):
        try:
            path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", getToken())
            if "file-data" not in request.files:
                return {'message': "missing file-data!"}, 400 
            fileUpload = request.files['file-data']
            uniqueName = str(time.time()) + secure_filename(fileUpload.filename)
            fileUpload.save(os.path.join(os.path.dirname(os.path.abspath(__file__)), uniqueName))

            dataFilePointer = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", uniqueName))
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
    @auth_required
    def get(self):
        # parameters
        try:
            param = []
            args_param = request.args

            # start time to time now
            if args_param.get('start-time') is None:
                search_data = ''
            else: 
                if args_param.get('start-time') == '':
                    return  {'message': "Error, incorrect date values"}, 400
                if datetime_iso(args_param.get('start-time')) == True:
                    param_1 = {"key": "created_at", "values": [f"{args_param.get('start-time')}"], "operator": "gt"}
                    param.append(param_1)
                else:
                    return {'message': "Error, incorrect date values"}, 400
            
            # score >
            if args_param.get('score') is None:
                search_data = ''
            else:
                if args_param.get('score') == '':
                    return {'message': "Error, incorrect date values"}, 400
                if args_param.get('score').isnumeric() == True:
                    param_2 = {"key": "x_opencti_score", "values": [f"{args_param.get('score')}"], "operator": "gt"}
                    param.append(param_2)

            # score <= 
            if args_param.get('score-lte') is None:
                search_data = ''
            else:
                if args_param.get('score-lte') == '':
                    return {'message': "Error, incorrect date values"}, 400
                if args_param.get('score-lte').isnumeric() == True:
                    param_3 = {"key": "x_opencti_score", "values": [f"{args_param.get('score-lte')}"], "operator": "lte"}
                    param.append(param_3)
            
            # search
            if args_param.get('search') == None:
                search_data = ''
            else:
                search_data = args_param.get('search')
        except Exception as exp:
            return  {'message': "Error, incorrect date values"}, 4001   

        # Core data
        try:
            opencti_api_client = OpenCTIApiClient(config['opencti']['url'], getToken())
            observables = opencti_api_client.stix_cyber_observable.list(search=str(search_data), getAll=False, filters=param, withPagination=True)

            data_json = json.dumps(observables, indent=4)
            data = json.loads(data_json)
            return {'data': data}, 201
        except Exception as exp:
            return  {'message': "failed!"}, 500

class GetFileData(Resource):

    @auth_required
    def get(self):
        # parameters
        try:
            param = []
            args_param = request.args

            # start time to time now
            if args_param.get('start-time') is None:
                search_data = ''
            else: 
                if args_param.get('start-time') == '':
                    return  {'message': "Error, incorrect date values"}, 400
                if datetime_iso(args_param.get('start-time')) == True:
                    param_1 = {"key": "created_at", "values": [f"{args_param.get('start-time')}"], "operator": "gt"}
                    param.append(param_1)
                else:
                    return {'message': "Error, incorrect date values"}, 400
            
            # score >
            if args_param.get('score') is None:
                search_data = ''
            else:
                if args_param.get('score') == '':
                    return {'message': "Error, incorrect date values"}, 400
                if args_param.get('score').isnumeric() == True:
                    param_2 = {"key": "x_opencti_score", "values": [f"{args_param.get('score')}"], "operator": "gt"}
                    param.append(param_2)

            # score <= 
            if args_param.get('score-lte') is None:
                search_data = ''
            else:
                if args_param.get('score-lte') == '':
                    return {'message': "Error, incorrect date values"}, 400
                if args_param.get('score-lte').isnumeric() == True:
                    param_3 = {"key": "x_opencti_score", "values": [f"{args_param.get('score-lte')}"], "operator": "lte"}
                    param.append(param_3)
            
            # search
            if args_param.get('search') == None:
                search_data = ''
            else:
                search_data = args_param.get('search')
        except Exception as exp:
            return  {'message': "Error, incorrect date values"}, 400   

        # Core data
        try:
            opencti_api_client = OpenCTIApiClient(config['opencti']['url'], getToken())
            observables = opencti_api_client.stix_cyber_observable.list(search=str(search_data), getAll=True, filters=param)
            data_json = json.dumps(observables, indent=4)
            # Write the bundle
            f = open("data.json", "w")
            f.write(data_json)
            f.close()
            path = 'data.json'

            return send_file(path, mimetype='application/json', as_attachment=True, conditional=True) 
            
        except Exception as exp:
            return  {'message': "failed!"}, 500  

  
api.add_resource(PushData, '/push-data')  
api.add_resource(PushFileData, '/push-file-data')
api.add_resource(GetData, '/get-data')
api.add_resource(GetFileData, '/get-file-stix2-data')
  
if __name__ == '__main__':
    app.run(host="0.0.0.0", port="5005", debug = True)