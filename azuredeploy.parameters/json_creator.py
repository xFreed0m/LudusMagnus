# This file generates different azuredeploy.parameters[N].json files to be used on the LudusMagnus env

import json
import string
import random

for z in range(0,100): # creating 100 files
    flags = []
    for i in range(0,10): # generating 10 random flags to be used
        x = ''.join(random.SystemRandom().choice(string.hexdigits) for _ in range(25))
        flags.insert(i, x)


    azuredeploy_parameters = [] # initializing the array for the json content
    azuredeploy_parameters = { # adding the content to the json file
        '$schema': 'https://schema.management.azure.com/schemas/2015-01-01/deploymentParameters.json#',
        'contentVersion': '1.0.0.0',
        'parameters': {
        "Flag0Value" : { "value": flags[0] },
        "Flag1Value" : { "value": flags[1] },
        "Flag2Value" : { "value": flags[2] },
        "Flag3Value" : { "value": flags[3] },
        "Flag4Value" : { "value": flags[4] },
        "Flag5Value" : { "value": flags[5] },
        "Flag6Value" : { "value": flags[6] },
        "Flag7Value" : { "value": flags[7] },
        "Flag8Value" : { "value": flags[8] },
        "Flag9Value" : { "value": flags[9] },
        }
    }
    with open('azuredeploy.parameters' + str(z) + '.json', 'w') as outfile: # creating the json files
        json.dump(azuredeploy_parameters, outfile, indent=1, sort_keys=True)