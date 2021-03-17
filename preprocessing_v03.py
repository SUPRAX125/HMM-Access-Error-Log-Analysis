#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Feb  4 19:52:46 2020

@author: root
"""

print("Running")
import pandas as pd
import json
from datetime import timedelta as td
from datetime import datetime
import sys

print("Success Running")
#fungsijsonread
def jsonreadtopandas(file):
    with open(file, 'r') as jsonfile:
        data = jsonfile.readlines()
        data = list(map(json.loads, data))
    return pd.DataFrame(data)

def jsonread(file):
    with open(file, 'r') as jsonfile:
        data = jsonfile.readlines()
        data = list(map(json.loads, data))
    return data

#daftar kolom file csv
log_kolom = ['IP Address', 'Timestamp', 'Method', 'HTTP Status Code', 'Request', 'Error', 'Error Message']
print("Success make column list")

#buat dataset dari kolom yang sudah dilist
#dataset_log = pd.DataFrame(columns= log_kolom)
#print("Success make dataframe")

errorfile = jsonreadtopandas('/media/root/New Volume/BelajarBung/Kuliah/Skripsi/coding/logstash_config/data/siakaderror.json')
#menghapus data null di errorfile
errorfile = errorfile.dropna()
errorfile = errorfile.reset_index(drop=True)
print("Success drop null value in errorfile")

#mengkonversi timestamp satu kolom sekaligus pada errorfile
for position in range(len(errorfile)):
    errorfile['timestamp'][position] = pd.to_datetime(errorfile['timestamp'][position][4:], format="%b %d %H:%M:%S %Y")
print("Success convert datetime in errorfile")

#mengurutkan data sesuai dengan timestamp di errorfile
errorfile = errorfile.sort_values(by=['timestamp'], ascending=True)
print("Success sorting timestamp in errorfile")

#membuat index direset dimulai dari 0, krn pas diurutin sesuai timestamp indexnya ngacak
errorfile = errorfile.reset_index(drop=True)
print("Success reset index in error and access file")

#variable untuk mulainya index errorfile
b=0
c=0
clientip=0
verb=0
response=0
jumlahdata=0
print("Success make b variable")

for datafile in range(1, len(sys.argv)):
    #buat dataset dari kolom yang sudah dilist
    dataset_log = pd.DataFrame(columns= log_kolom)
    print("Success make dataframe", sys.argv[datafile])

    #print(sys.argv[datafile])

    #membaca file json dengan fungsi
    accessfile = jsonread(sys.argv[datafile])
    print("Success read json file")

    #mengurutkan data sesuai dengan timestamp di accessfile
    accessfile = sorted(accessfile, key=lambda x: datetime.strptime(x['timestamp'][:-6], '%d/%b/%Y:%H:%M:%S'))
    print("Success sorting timestamp in accessfile")
    print(len(accessfile))

    for a in range(len(accessfile)):
        #if there's null in ip address, http status code, and method will not write in dataset
        if 'clientip' not in accessfile[a] or  'response' not in accessfile[a] or 'verb' not in accessfile[a]:
            if 'clientip' not in accessfile[a]:
                 clientip += 1
            if 'verb' not in accessfile[a]:
                 verb += 1
            if 'response' not in accessfile[a]:
                 response += 1
            print("a: ", a, "b: ",b, "Success continue which clientip, response, and verb has no value")
            c+=1
            continue
        else:
            #convert timestamp column in accessfile into the real timestamp
            timestampaccess = datetime.strptime(accessfile[a]['timestamp'][:-6], '%d/%b/%Y:%H:%M:%S')
            if b < len(errorfile):
                timestamperror = errorfile['timestamp'][b]
                #if there's access and error same at the ip and timestamp with tolerance -3 second and +3second then
                #errorfile will write in error and error message column into dataset
                if (accessfile[a]['clientip'] == errorfile['clientip'][b]) and ((timestampaccess >= timestamperror - td(seconds=3)) and (timestampaccess <= timestamperror + td(seconds=3))):
                    dataset_log = dataset_log.append({'IP Address': accessfile[a]['clientip'], 'Timestamp': timestampaccess, 'Method': accessfile[a]['verb'],
                                              'HTTP Status Code': accessfile[a]['response'], 'Request': accessfile[a]['request'], 'Error': 1, 
                                              'Error Message': errorfile['errormsg'][b]}, ignore_index=True)
                    #increase for errorfile index if found same ip and same timestamp
                    b+=1
                    jumlahdata+=1
                    print("a: ",a, "b: ", b,"c: ",c, "jumlah data: ",jumlahdata)
                #if there's not found ip and timestamp on accessfile and errorfile, error and error message will written 0 and Non Error
                else:
                   dataset_log = dataset_log.append({'IP Address': accessfile[a]['clientip'], 'Timestamp': timestampaccess, 'Method': accessfile[a]['verb'],
                                               'HTTP Status Code': accessfile[a]['response'], 'Request': accessfile[a]['request'],
                                               'Error': 0, 'Error Message': "Non Error"}, ignore_index=True)
                   jumlahdata+=1
                   print("a: ",a, "b: ", b,"c: ",c, "jumlah data: ",jumlahdata)
            else:
                dataset_log = dataset_log.append({'IP Address': accessfile[a]['clientip'], 'Timestamp': timestampaccess, 'Method': accessfile[a]['verb'],
                                            'HTTP Status Code': accessfile[a]['response'], 'Request': accessfile[a]['request'], 
                                            'Error': 0, 'Error Message': "Non Error"}, ignore_index=True)
                jumlahdata+=1
                print("a: ",a, "b: ", b,"c: ",c, "jumlah data: ",jumlahdata)
        if a % 300000 == 0 and a != 0:
            namecsv = "/media/root/New Volume/BelajarBung/Kuliah/Skripsi/coding/logstash_config/data/Access json/csv file/"+sys.argv[datafile]+"-webserverlog-"+str(a)+".csv"
            dataset_log.to_csv(namecsv)
            print('Success integration', a, 'in', namecsv)
            dataset_log = pd.DataFrame(columns=log_kolom)

    namecsv = "/media/root/New Volume/BelajarBung/Kuliah/Skripsi/coding/logstash_config/data/Access json/csv file/"+sys.argv[datafile]+"-webserverlog-"+str(a)+".csv"
    dataset_log.to_csv(namecsv)
    print("Success integration", a, "in", namecsv)

print("Success make csv")
print("Clear Running")
print("Jumlah cleaning:",c)
print("Jumlah cleaning clientip: ", clientip)
print("Jumlah cleaning verb: ", verb)
print("Jumlah cleaning response: ", response)
