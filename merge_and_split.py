#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Mar 19 22:52:29 2020

@author: root
"""


import sys
import pandas as pd

#bikin dataset temporari
new_dataset = pd.DataFrame(columns=['IP Address', 'Timestamp', 'Method', 'HTTP Status Code', 'Request',
       'Error', 'Error Message', 'Class'])

#ngemerge semua data
for dataset in range(1, len(sys.argv)):
    dataset_temp =  pd.read_csv(sys.argv[dataset])
    new_dataset = pd.concat([new_dataset, dataset_temp], axis=0)
    print("file",sys.argv[dataset],"completely merge")
    
print("\n")
#ngitung train testnya
train70 = round((len(new_dataset)*70)/100)
test30 = round((len(new_dataset)*30)/100)

train80 = round((len(new_dataset)*80)/100)
test20 = round((len(new_dataset)*20)/100)

train90 = round((len(new_dataset)*90)/100)
test10 = round((len(new_dataset)*10)/100)

#ngebagi train testnya
dataset_train_70 = new_dataset.head(train70)
dataset_test_30 = new_dataset.tail(test30)

dataset_train_80 = new_dataset.head(train80)
dataset_test_20 = new_dataset.tail(test20)

dataset_train_90 = new_dataset.head(train90)
dataset_test_10 = new_dataset.tail(test10)

#ngeprint hasil perjumlahan
print("jumlah row: ", len(new_dataset))
print("\n")

print("training 70%\t: ",train70)
print("testing 30%\t:", test30)

print("training 80%\t: ",train80)
print("testing 20%\t:", test20)

print("training 90%\t: ",train90)
print("testing 10%\t:", test10)

print("\n")
#-----------cek bener pembagiannya-----------------
print("training datanya 70%\t: ",len(dataset_train_70))
print("testing datanya 30%\t:", len(dataset_test_30))

print("training datanya 80%\t: ",len(dataset_train_80))
print("testing datanya 20%\t:", len(dataset_test_20))

print("training datanya 90%\t: ",len(dataset_train_90))
print("testing datanya10%\t:", len(dataset_test_10))
print("\n")

dataset_train_70.to_csv('train_test/webserverlog_train_70%.csv', index=False)
dataset_test_30.to_csv('train_test/webserverlog_test_30%.csv', index=False)
print("clear make train test 70% 30%")

dataset_train_80.to_csv('train_test/webserverlog_train_80%.csv', index=False)
dataset_test_20.to_csv('train_test/webserverlog_test_20%.csv', index=False)
print("clear make train test 80% 20%")


dataset_train_90.to_csv('train_test/webserverlog_train_90%.csv', index=False)
dataset_test_10.to_csv('train_test/webserverlog_test_10%.csv', index=False)
print("clear make train test 90% 10%")
