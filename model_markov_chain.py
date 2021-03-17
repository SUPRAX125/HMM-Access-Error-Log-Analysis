#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Feb 19 18:05:33 2020

@author: root
"""

import datetime
timestart = datetime.datetime.now()
print("time start: ",timestart)

import pandas as pd
from datetime import timedelta as td
from sklearn.metrics import confusion_matrix
from sklearn.metrics import accuracy_score


#buka data
logserver = pd.read_csv('/media/root/New Volume/BelajarBung/Kuliah/Skripsi/coding/logstash_config/data/1 Data Clean/csv file/train_test/webserverlog_train_90%.csv')
testlogserver = pd.read_csv('/media/root/New Volume/BelajarBung/Kuliah/Skripsi/coding/logstash_config/data/1 Data Clean/csv file/train_test/webserverlog_test_10%.csv')
# logserver = pd.read_csv('webserverlog_train_70%.csv')
# testlogserver = pd.read_csv('webserverlog_test_30%.csv')
print("Train 90% Testing 10% full")

#mengurutkan data berdasarkan IP dan Timestamp yang berbeda
logserver = logserver.sort_values(by=['IP Address', 'Timestamp'], ascending=True)
testlogserver = testlogserver.sort_values(by=['IP Address', 'Timestamp'], ascending=True)
logserver = logserver.reset_index(drop=True)
testlogserver = testlogserver.reset_index(drop=True)


# menghasilkan jumlah class
class_counts = logserver['Class'].value_counts()

# masukkin jumlah class attack dan non attack
attacks = class_counts['Attack']
non_attacks = class_counts['Non Attack']

#convert HTTP Status Code(int) and Error(int) to string
logserver['HTTP Status Code'] = logserver['HTTP Status Code'].apply(str)
testlogserver['HTTP Status Code'] = testlogserver['HTTP Status Code'].apply(str)

testlogserverclass = testlogserver['Class']
testlogserverclasspredict = pd.DataFrame(columns=['Class'])
testlogserverdata = testlogserver.drop('Class', axis=1)

#-------------------------------modeling probability--------------------------

#(attack, attack),(attack, non attack),(non attack, attack) (non attack, non attack)
H_state = [[0,0],[0,0]]
H_state_prob = [[0,0], [0,0]]

#state 1 GET 2xx 0 [0,0]
#state 2 GET 2xx 1 [0,1]
#state 3 GET 3xx 0 [1,0]
#state 4 GET 3xx 1 [1,1]
#state 5 GET 4xx 0 [2,0]
#state 6 GET 4xx 1 [2,1]
#state 7 GET 5xx 0 [3,0]
#state 8 GET 5xx 1 [3,1]
#state 9 POST 2xx 0 [4,0]
#state 10 POST 2xx 1 [4,1]
#state 11 POST 3xx 0 [5,0]
#state 12 POST 3xx 1 [5,1]
#state 13 POST 4xx 0 [6,0]
#state 14 POST 4xx 1 [6,1]
#state 15 POST 5xx 0 [7,0]
#state 16 POST 5xx 1 [7,1]
E_state = [[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0]]
E_state_prob = [[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0]]

#--------------------------------Hidden State (Transition Probability)--------------------------------------

#mencari jumlah transisi hidden state attack dan non attack
for b in range(len(logserver)-1):
    if logserver['IP Address'][b] == logserver['IP Address'][b+1] and pd.to_datetime(logserver['Timestamp'][b], format='%Y-%m-%d %H:%M') <= pd.to_datetime(logserver['Timestamp'][b+1], format='%Y-%m-%d %H:%M') + td(hours=2):
        if logserver['Class'][b] == 'Attack' and logserver['Class'][b+1] == 'Attack':
            H_state[0][0] += 1
            
        elif logserver['Class'][b] == 'Attack' and logserver['Class'][b+1] == 'Non Attack':
            H_state[0][1] += 1
            
        elif logserver['Class'][b] == 'Non Attack' and logserver['Class'][b+1] == 'Attack':
            H_state[1][0] += 1
        
        elif logserver['Class'][b] == 'Non Attack' and logserver['Class'][b+1] == 'Non Attack':
            H_state[1][1] += 1
        else:
            continue
        
#attack state jumlah kelasnya
attack_trans = H_state[0][0] + H_state[0][1]
non_attack_trans = H_state[1][0] + H_state[1][1]

#attack state probability
H_state_prob[0][0] = H_state[0][0]/attack_trans
H_state_prob[0][1] = H_state[0][1]/attack_trans

#non attack state probability
H_state_prob[1][0] = H_state[1][0]/non_attack_trans
H_state_prob[1][1] = H_state[1][1]/non_attack_trans

#------------------------Observation State (Emission Probability)------------------------------------------------
#mencari jumlah emisi dari 16 state terhadap kelas attack dan non attack
for a in range(len(logserver)):
    #state 1 GET 2xx 0
    if logserver['Method'][a] == "GET" and logserver['HTTP Status Code'][a][0] == "2" and logserver['Error'][a] == 0 and logserver['Class'][a] == "Attack":
        E_state[0][0] += 1
    elif logserver['Method'][a] == "GET" and logserver['HTTP Status Code'][a][0] == "2" and logserver['Error'][a] == 0 and logserver['Class'][a] == "Non Attack":
        E_state[0][1] += 1
        
    #state 2 GET 2xx 1
    elif logserver['Method'][a] == "GET" and logserver['HTTP Status Code'][a][0] == "2" and logserver['Error'][a] == 1 and logserver['Class'][a] == "Attack":
        E_state[1][0] += 1
    elif logserver['Method'][a] == "GET" and logserver['HTTP Status Code'][a][0] == "2" and logserver['Error'][a] == 1 and logserver['Class'][a] == "Non Attack":
        E_state[1][1] += 1
    
    #state 3 GET 3xx 0
    elif logserver['Method'][a] == "GET" and logserver['HTTP Status Code'][a][0] == "3" and logserver['Error'][a] == 0 and logserver['Class'][a] == "Attack":
        E_state[2][0] += 1
    elif logserver['Method'][a] == "GET" and logserver['HTTP Status Code'][a][0] == "3" and logserver['Error'][a] == 0 and logserver['Class'][a] == "Non Attack":
        E_state[2][1] += 1
        
    #state 4 GET 3xx 1
    elif logserver['Method'][a] == "GET" and logserver['HTTP Status Code'][a][0] == "3" and logserver['Error'][a] == 1 and logserver['Class'][a] == "Attack":
        E_state[3][0] += 1
    elif logserver['Method'][a] == "GET" and logserver['HTTP Status Code'][a][0] == "3" and logserver['Error'][a] == 1 and logserver['Class'][a] == "Non Attack":
        E_state[3][1] += 1
        
    #state 5 GET 4xx 0
    elif logserver['Method'][a] == "GET" and logserver['HTTP Status Code'][a][0] == "4" and logserver['Error'][a] == 0  and logserver['Class'][a] == "Attack":
        E_state[4][0] += 1
    elif logserver['Method'][a] == "GET" and logserver['HTTP Status Code'][a][0] == "4" and logserver['Error'][a] == 0 and logserver['Class'][a] == "Non Attack":
        E_state[4][1] += 1
        
    #state 6 GET 4xx 1
    elif logserver['Method'][a] == "GET" and logserver['HTTP Status Code'][a][0] == "4" and logserver['Error'][a] == 1 and logserver['Class'][a] == "Attack":
        E_state[5][0] += 1
    elif logserver['Method'][a] == "GET" and logserver['HTTP Status Code'][a][0] == "4" and logserver['Error'][a] == 1 and logserver['Class'][a] == "Non Attack":
        E_state[5][1] += 1
        
    #state 7 GET 5xx 0
    elif logserver['Method'][a] == "GET" and logserver['HTTP Status Code'][a][0] == "5" and logserver['Error'][a] == 0 and logserver['Class'][a] == "Attack":
        E_state[6][0] += 1
    elif logserver['Method'][a] == "GET" and logserver['HTTP Status Code'][a][0] == "5" and logserver['Error'][a] == 0 and logserver['Class'][a] == "Non Attack":
        E_state[6][1] += 1
        
    #state 8 GET 5xx 1
    elif logserver['Method'][a] == "GET" and logserver['HTTP Status Code'][a][0] == "5" and logserver['Error'][a] == 1 and logserver['Class'][a] == "Attack":
        E_state[7][0] += 1
    elif logserver['Method'][a] == "GET" and logserver['HTTP Status Code'][a][0] == "5" and logserver['Error'][a] == 1 and logserver['Class'][a] == "Non Attack":
        E_state[7][1] += 1
        
    #state 9 POST 2xx 0
    elif logserver['Method'][a] == "POST" and logserver['HTTP Status Code'][a][0] == "2" and logserver['Error'][a] == 0 and logserver['Class'][a] == "Attack":
        E_state[8][0] += 1
    elif logserver['Method'][a] == "POST" and logserver['HTTP Status Code'][a][0] == "2" and logserver['Error'][a] == 0 and logserver['Class'][a] == "Non Attack":
        E_state[8][1] += 1
    
    #state 10
    elif logserver['Method'][a] == "POST" and logserver['HTTP Status Code'][a][0] == "2" and logserver['Error'][a] == 1 and logserver['Class'][a] == "Attack":
        E_state[9][0] += 1
    elif logserver['Method'][a] == "POST" and logserver['HTTP Status Code'][a][0] == "2" and logserver['Error'][a] == 1 and logserver['Class'][a] == "Non Attack":
        E_state[9][1] += 1
        
    #state 11
    elif logserver['Method'][a] == "POST" and logserver['HTTP Status Code'][a][0] == "3" and logserver['Error'][a] == 0 and logserver['Class'][a] == "Attack":
        E_state[10][0] += 1
    elif logserver['Method'][a] == "POST" and logserver['HTTP Status Code'][a][0] == "3" and logserver['Error'][a] == 0 and logserver['Class'][a] == "Non Attack":
        E_state[10][1] += 1
        
    #state 12
    elif logserver['Method'][a] == "POST" and logserver['HTTP Status Code'][a][0] == "3" and logserver['Error'][a] == 1 and logserver['Class'][a] == "Attack":
        E_state[11][0] += 1
    elif logserver['Method'][a] == "POST" and logserver['HTTP Status Code'][a][0] == "3" and logserver['Error'][a] == 1 and logserver['Class'][a] == "Non Attack":
        E_state[11][1] += 1
        
    #state 13
    elif logserver['Method'][a] == "POST" and logserver['HTTP Status Code'][a][0] == "4" and logserver['Error'][a] == 0 and logserver['Class'][a] == "Attack":
        E_state[12][0] += 1
    elif logserver['Method'][a] == "POST" and logserver['HTTP Status Code'][a][0] == "4" and logserver['Error'][a] == 0 and logserver['Class'][a] == "Non Attack":
        E_state[12][1] += 1
        
    #state 14
    elif logserver['Method'][a] == "POST" and logserver['HTTP Status Code'][a][0] == "4" and logserver['Error'][a] == 1 and logserver['Class'][a] == "Attack":
        E_state[13][0] += 1
    elif logserver['Method'][a] == "POST" and logserver['HTTP Status Code'][a][0] == "4" and logserver['Error'][a] == 1 and logserver['Class'][a] == "Non Attack":
        E_state[13][1] += 1
        
    #state 15
    elif logserver['Method'][a] == "POST" and logserver['HTTP Status Code'][a][0] == "5" and logserver['Error'][a] == 0 and logserver['Class'][a] == "Attack":
        E_state[14][0] += 1
    elif logserver['Method'][a] == "POST" and logserver['HTTP Status Code'][a][0] == "5" and logserver['Error'][a] == 0 and logserver['Class'][a] == "Non Attack":
        E_state[14][1] += 1
        
    #state 16
    elif logserver['Method'][a] == "POST" and logserver['HTTP Status Code'][a][0] == "5" and logserver['Error'][a] == 1 and logserver['Class'][a] == "Attack":
        E_state[15][0] += 1
    elif logserver['Method'][a] == "POST" and logserver['HTTP Status Code'][a][0] == "5" and logserver['Error'][a] == 1 and logserver['Class'][a] == "Non Attack":
        E_state[15][1] += 1

#jumlah kelas attack pada emisi
E_attack = 0
E_non_attack = 0
E_attack = sum(E_state[x][0] for x in range(len(E_state)))
E_non_attack = sum(E_state[x][1] for x in range(len(E_state)))

#ngecek ada null di index bagian attack (list[x][0])
def check_null_attack(problist):
    statusattack = False
    for alist in range(len(problist)):
        if problist[alist][0] == 0:
            statusattack = True
            break
    return statusattack
        
#ngecek ada null di index bagian non attack (list[x][1])
def check_null_non_attack(problist):
    statusnonattack = False
    for alist in range(len(problist)):
        if problist[alist][1] == 0:
            statusnonattack = True
            break
    return statusnonattack
        
#fungsi laplacian smoothing
def laplacian_smoothing(data):
    if check_null_attack(data):
        for attack_count in range(len(data)):
            data[attack_count][0] += 1
        global E_attack
        E_attack += attack_count+1
        print(E_attack, len(data), attack_count)
            
    if check_null_non_attack(data):
        for non_attack_count in range(len(data)):
            data[non_attack_count][1] += 1
        global E_non_attack
        E_non_attack += non_attack_count+1
        print(E_non_attack, len(data),non_attack_count)
        
laplacian_smoothing(E_state)

for prob in range(len(E_state_prob)):
    #attack prob
    E_state_prob[prob][0] = E_state[prob][0]/E_attack
    
    #non attack prob
    E_state_prob[prob][1] = E_state[prob][1]/E_non_attack #state 1

#menghitung jumlah probabilitas attack dg 16 state = 1 dan non attack dg 16 state = 1
# e_prob_attack = sum(E_state_prob[g][0] for g in range(len(E_state_prob)))
# e_prob_non_attack = sum(E_state_prob[g][1] for g in range(len(E_state_prob)))
    
print("selesai membuat model probabilitas")

#-----------------------testing viterbi algorithm--------------------------------------

atk_prob = attacks/len(logserver)
natk_prob = non_attacks/len(logserver)

result_atk_prob = []
result_natk_prob = []

arraybiasa = 0

for a in range(len(testlogserverdata)):
    if a == 0:
        maxattack = 0
        maxnonattack = 0
        
        hitung_atk_to_atk = 0
        hitung_natk_to_atk = 0
        hitung_atk_to_natk = 0
        hitung_natk_to_natk = 0
        
        #state 1 GET 2xx 0
        if testlogserverdata['Method'][0] == "GET" and testlogserverdata['HTTP Status Code'][0][0] == "2" and testlogserverdata['Error'][0] == 0:
            maxattack = E_state_prob[0][0] * atk_prob
            result_atk_prob.append(maxattack)
            maxnonattack = E_state_prob[0][1] * natk_prob
            result_natk_prob.append(maxnonattack)
            # arraybiasa += 1
            # print('a: ',a, "array: ",arraybiasa)
            
        #state 2 GET 2xx 1
        elif testlogserverdata['Method'][0] == "GET" and testlogserverdata['HTTP Status Code'][0][0] == "2" and testlogserverdata['Error'][0] == 1:
            maxattack = E_state_prob[1][0] * atk_prob
            result_atk_prob.append(maxattack)
            maxnonattack = E_state_prob[1][1] * natk_prob
            result_natk_prob.append(maxnonattack)
            # arraybiasa += 1
            # print('a: ',a, "array: ",arraybiasa)
        
        #state 3 GET 3xx 0
        elif testlogserverdata['Method'][0] == "GET" and testlogserverdata['HTTP Status Code'][0][0] == "3" and testlogserverdata['Error'][0] == 0:
            maxattack = E_state_prob[2][0] * atk_prob
            result_atk_prob.append(maxattack)
            maxnonattack = E_state_prob[2][1] * natk_prob
            result_natk_prob.append(maxnonattack)
            # arraybiasa += 1
            # print('a: ',a, "array: ",arraybiasa)
            
        #state 4 GET 3xx 1
        elif testlogserverdata['Method'][0] == "GET" and testlogserverdata['HTTP Status Code'][0][0] == "3" and testlogserverdata['Error'][0] == 1:
            maxattack = E_state_prob[3][0] * atk_prob
            result_atk_prob.append(maxattack)
            maxnonattack = E_state_prob[3][1] * natk_prob
            result_natk_prob.append(maxnonattack)
            # arraybiasa += 1
            # print('a: ',a, "array: ",arraybiasa)
            
        #state 5 GET 4xx 0
        elif testlogserverdata['Method'][0] == "GET" and testlogserverdata['HTTP Status Code'][0][0] == "4" and testlogserverdata['Error'][0] == 0:
            maxattack = E_state_prob[4][0] * atk_prob
            result_atk_prob.append(maxattack)
            maxnonattack = E_state_prob[4][1] * natk_prob
            result_natk_prob.append(maxnonattack)
            # arraybiasa += 1
            # print('a: ',a, "array: ",arraybiasa)
            
        #state 6 GET 4xx 1
        elif testlogserverdata['Method'][0] == "GET" and testlogserverdata['HTTP Status Code'][0][0] == "4" and testlogserverdata['Error'][0] == 1:
            maxattack = E_state_prob[5][0] * atk_prob
            result_atk_prob.append(maxattack)
            maxnonattack = E_state_prob[5][1] * natk_prob
            result_natk_prob.append(maxnonattack)
            # arraybiasa += 1
            # print('a: ',a, "array: ",arraybiasa)
            
        #state 7 GET 5xx 0
        elif testlogserverdata['Method'][0] == "GET" and testlogserverdata['HTTP Status Code'][0][0] == "5" and testlogserverdata['Error'][0] == 0:
            maxattack = E_state_prob[6][0] * atk_prob
            result_atk_prob.append(maxattack)
            maxnonattack = E_state_prob[6][1] * natk_prob
            result_natk_prob.append(maxnonattack)
            # arraybiasa += 1
            # print('a: ',a, "array: ",arraybiasa)
            
        #state 8 GET 5xx 1
        elif testlogserverdata['Method'][0] == "GET" and testlogserverdata['HTTP Status Code'][0][0] == "5" and testlogserverdata['Error'][0] == 1:
            maxattack = E_state_prob[7][0] * atk_prob
            result_atk_prob.append(maxattack)
            maxnonattack = E_state_prob[7][1] * natk_prob
            result_natk_prob.append(maxnonattack)
            # arraybiasa += 1
            # print('a: ',a, "array: ",arraybiasa)
            
        #state 9 POST 2xx 0
        elif testlogserverdata['Method'][0] == "POST" and testlogserverdata['HTTP Status Code'][0][0] == "2" and testlogserverdata['Error'][0] == 0:
            maxattack = E_state_prob[8][0] * atk_prob
            result_atk_prob.append(maxattack)
            maxnonattack = E_state_prob[8][1] * natk_prob
            result_natk_prob.append(maxnonattack)
            # arraybiasa += 1
            # print('a: ',a, "array: ",arraybiasa)
        
        #state 10
        elif testlogserverdata['Method'][0] == "POST" and testlogserverdata['HTTP Status Code'][0][0] == "2" and testlogserverdata['Error'][0] == 1:
            maxattack = E_state_prob[9][0] * atk_prob
            result_atk_prob.append(maxattack)
            maxnonattack = E_state_prob[9][1] * natk_prob
            result_natk_prob.append(maxnonattack)
            # arraybiasa += 1
            # print('a: ',a, "array: ",arraybiasa)
            
        #state 11
        elif testlogserverdata['Method'][0] == "POST" and testlogserverdata['HTTP Status Code'][0][0] == "3" and testlogserverdata['Error'][0] == 0:
            maxattack = E_state_prob[10][0] * atk_prob
            result_atk_prob.append(maxattack)
            maxnonattack = E_state_prob[10][1] * natk_prob
            result_natk_prob.append(maxnonattack)
            # arraybiasa += 1
            # print('a: ',a, "array: ",arraybiasa)
            
        #state 12
        elif testlogserverdata['Method'][0] == "POST" and testlogserverdata['HTTP Status Code'][0][0] == "3" and testlogserverdata['Error'][0] == 1:
            maxattack = E_state_prob[11][0] * atk_prob
            result_atk_prob.append(maxattack)
            maxnonattack = E_state_prob[11][1] * natk_prob
            result_natk_prob.append(maxnonattack)
            # arraybiasa += 1
            # print('a: ',a, "array: ",arraybiasa)
            
        #state 13
        elif testlogserverdata['Method'][0] == "POST" and testlogserverdata['HTTP Status Code'][0][0] == "4" and testlogserverdata['Error'][0] == 0:
            maxattack = E_state_prob[12][0] * atk_prob
            result_atk_prob.append(maxattack)
            maxnonattack = E_state_prob[12][1] * natk_prob
            result_natk_prob.append(maxnonattack)
            # arraybiasa += 1
            # print('a: ',a, "array: ",arraybiasa)
            
        #state 14
        elif testlogserverdata['Method'][0] == "POST" and testlogserverdata['HTTP Status Code'][0][0] == "4" and testlogserverdata['Error'][0] == 1:
            maxattack = E_state_prob[13][0] * atk_prob
            result_atk_prob.append(maxattack)
            maxnonattack = E_state_prob[13][1] * natk_prob
            result_natk_prob.append(maxnonattack)
            # arraybiasa += 1
            # print('a: ',a, "array: ",arraybiasa)
            
        #state 15
        elif testlogserverdata['Method'][0] == "POST" and testlogserverdata['HTTP Status Code'][0][0] == "5" and testlogserverdata['Error'][0] == 0:
            maxattack = E_state_prob[14][0] * atk_prob
            result_atk_prob.append(maxattack)
            maxnonattack = E_state_prob[14][1] * natk_prob
            result_natk_prob.append(maxnonattack)
            # arraybiasa += 1
            # print('a: ',a, "array: ",arraybiasa)
            
        #state 16
        elif testlogserverdata['Method'][0] == "POST" and testlogserverdata['HTTP Status Code'][0][0] == "5" and testlogserverdata['Error'][0] == 1:
            maxattack = E_state_prob[15][0] * atk_prob
            result_atk_prob.append(maxattack)
            maxnonattack = E_state_prob[15][1] * natk_prob
            result_natk_prob.append(maxnonattack)
            # arraybiasa += 1
            # print('a: ',a, "array: ",arraybiasa)
            
        else:
            print("error di index", a)
    
    elif (testlogserverdata["IP Address"][a] != testlogserverdata["IP Address"][a-1]) or (testlogserverdata["IP Address"][a] == testlogserverdata["IP Address"][a-1] and pd.to_datetime(testlogserverdata['Timestamp'][a], format='%Y-%m-%d %H:%M') >= pd.to_datetime(testlogserverdata['Timestamp'][a-1], format='%Y-%m-%d %H:%M') + td(hours=2)):
        maxattack = 0
        maxnonattack = 0
        
        hitung_atk_to_atk = 0
        hitung_natk_to_atk = 0
        hitung_atk_to_natk = 0
        hitung_natk_to_natk = 0
        
        #state 1 GET 2xx 0
        if testlogserverdata['Method'][a] == "GET" and testlogserverdata['HTTP Status Code'][a][0] == "2" and testlogserverdata['Error'][a] == 0:
            maxattack = E_state_prob[0][0] * atk_prob
            result_atk_prob.append(maxattack)
            maxnonattack = E_state_prob[0][1] * natk_prob
            result_natk_prob.append(maxnonattack)

        #state 2 GET 2xx 1
        elif testlogserverdata['Method'][a] == "GET" and testlogserverdata['HTTP Status Code'][a][0] == "2" and testlogserverdata['Error'][a] == 1:
            maxattack = E_state_prob[1][0] * atk_prob
            result_atk_prob.append(maxattack)
            maxnonattack = E_state_prob[1][1] * natk_prob
            result_natk_prob.append(maxnonattack)

        #state 3 GET 3xx 0
        elif testlogserverdata['Method'][a] == "GET" and testlogserverdata['HTTP Status Code'][a][0] == "3" and testlogserverdata['Error'][a] == 0:
            maxattack = E_state_prob[2][0] * atk_prob
            result_atk_prob.append(maxattack)
            maxnonattack = E_state_prob[2][1] * natk_prob
            result_natk_prob.append(maxnonattack)

        #state 4 GET 3xx 1
        elif testlogserverdata['Method'][a] == "GET" and testlogserverdata['HTTP Status Code'][a][0] == "3" and testlogserverdata['Error'][a] == 1:
            maxattack = E_state_prob[3][0] * atk_prob
            result_atk_prob.append(maxattack)
            maxnonattack = E_state_prob[3][1] * natk_prob
            result_natk_prob.append(maxnonattack)

        #state 5 GET 4xx 0
        elif testlogserverdata['Method'][a] == "GET" and testlogserverdata['HTTP Status Code'][a][0] == "4" and testlogserverdata['Error'][a] == 0:
            maxattack = E_state_prob[4][0] * atk_prob
            result_atk_prob.append(maxattack)
            maxnonattack = E_state_prob[4][1] * natk_prob
            result_natk_prob.append(maxnonattack)

        #state 6 GET 4xx 1
        elif testlogserverdata['Method'][a] == "GET" and testlogserverdata['HTTP Status Code'][a][0] == "4" and testlogserverdata['Error'][a] == 1:
            maxattack = E_state_prob[5][0] * atk_prob
            result_atk_prob.append(maxattack)
            maxnonattack = E_state_prob[5][1] * natk_prob
            result_natk_prob.append(maxnonattack)

        #state 7 GET 5xx 0
        elif testlogserverdata['Method'][a] == "GET" and testlogserverdata['HTTP Status Code'][a][0] == "5" and testlogserverdata['Error'][a] == 0:
            maxattack = E_state_prob[6][0] * atk_prob
            result_atk_prob.append(maxattack)
            maxnonattack = E_state_prob[6][1] * natk_prob
            result_natk_prob.append(maxnonattack)

        #state 8 GET 5xx 1
        elif testlogserverdata['Method'][a] == "GET" and testlogserverdata['HTTP Status Code'][a][0] == "5" and testlogserverdata['Error'][a] == 1:
            maxattack = E_state_prob[7][0] * atk_prob
            result_atk_prob.append(maxattack)
            maxnonattack = E_state_prob[7][1] * natk_prob
            result_natk_prob.append(maxnonattack)

        #state 9 POST 2xx 0
        elif testlogserverdata['Method'][a] == "POST" and testlogserverdata['HTTP Status Code'][a][0] == "2" and testlogserverdata['Error'][a] == 0:
            maxattack = E_state_prob[8][0] * atk_prob
            result_atk_prob.append(maxattack)
            maxnonattack = E_state_prob[8][1] * natk_prob
            result_natk_prob.append(maxnonattack)

        #state 10
        elif testlogserverdata['Method'][a] == "POST" and testlogserverdata['HTTP Status Code'][a][0] == "2" and testlogserverdata['Error'][a] == 1:
            maxattack = E_state_prob[9][0] * atk_prob
            result_atk_prob.append(maxattack)
            maxnonattack = E_state_prob[9][1] * natk_prob
            result_natk_prob.append(maxnonattack)

        #state 11
        elif testlogserverdata['Method'][a] == "POST" and testlogserverdata['HTTP Status Code'][a][0] == "3" and testlogserverdata['Error'][a] == 0:
            maxattack = E_state_prob[10][0] * atk_prob
            result_atk_prob.append(maxattack)
            maxnonattack = E_state_prob[10][1] * natk_prob
            result_natk_prob.append(maxnonattack)

        #state 12
        elif testlogserverdata['Method'][a] == "POST" and testlogserverdata['HTTP Status Code'][a][0] == "3" and testlogserverdata['Error'][a] == 1:
            maxattack = E_state_prob[11][0] * atk_prob
            result_atk_prob.append(maxattack)
            maxnonattack = E_state_prob[11][1] * natk_prob
            result_natk_prob.append(maxnonattack)
            
        #state 13
        elif testlogserverdata['Method'][a] == "POST" and testlogserverdata['HTTP Status Code'][a][0] == "4" and testlogserverdata['Error'][a] == 0:
            maxattack = E_state_prob[12][0] * atk_prob
            result_atk_prob.append(maxattack)
            maxnonattack = E_state_prob[12][1] * natk_prob
            result_natk_prob.append(maxnonattack)

        #state 14
        elif testlogserverdata['Method'][a] == "POST" and testlogserverdata['HTTP Status Code'][a][0] == "4" and testlogserverdata['Error'][a] == 1:
            maxattack = E_state_prob[13][0] * atk_prob
            result_atk_prob.append(maxattack)
            maxnonattack = E_state_prob[13][1] * natk_prob
            result_natk_prob.append(maxnonattack)
            
        #state 15
        elif testlogserverdata['Method'][a] == "POST" and testlogserverdata['HTTP Status Code'][a][0] == "5" and testlogserverdata['Error'][a] == 0:
            maxattack = E_state_prob[14][0] * atk_prob
            result_atk_prob.append(maxattack)
            maxnonattack = E_state_prob[14][1] * natk_prob
            result_natk_prob.append(maxnonattack)
            
        #state 16
        elif testlogserverdata['Method'][a] == "POST" and testlogserverdata['HTTP Status Code'][a][0] == "5" and testlogserverdata['Error'][a] == 1:
            maxattack = E_state_prob[15][0] * atk_prob
            result_atk_prob.append(maxattack)
            maxnonattack = E_state_prob[15][1] * natk_prob
            result_natk_prob.append(maxnonattack)
        else:
            print("error di index", a)
        
    elif testlogserverdata["IP Address"][a] == testlogserverdata["IP Address"][a-1] and pd.to_datetime(testlogserverdata['Timestamp'][a], format='%Y-%m-%d %H:%M') <= pd.to_datetime(testlogserverdata['Timestamp'][a-1], format='%Y-%m-%d %H:%M') + td(hours=2):
        #state 1 GET 2xx 0
        if testlogserverdata['Method'][a] == "GET" and testlogserverdata['HTTP Status Code'][a][0] == "2" and testlogserverdata['Error'][a] == 0:
            hitung_atk_to_atk = maxattack * H_state_prob[0][0] * E_state_prob[0][0]
            hitung_natk_to_atk = maxnonattack * H_state_prob[1][0] * E_state_prob[0][0]
            
            hitung_atk_to_natk = maxattack * H_state_prob[0][1] * E_state_prob[0][1]
            hitung_natk_to_natk = maxnonattack * H_state_prob[1][1] * E_state_prob[0][1]
            
            maxattack = max(hitung_atk_to_atk, hitung_natk_to_atk)
            maxnonattack = max(hitung_atk_to_natk, hitung_natk_to_natk)
        
            result_atk_prob.append(maxattack)
            result_natk_prob.append(maxnonattack)
            
        #state 2 GET 2xx 1
        elif testlogserverdata['Method'][a] == "GET" and testlogserverdata['HTTP Status Code'][a][0] == "2" and testlogserverdata['Error'][a] == 1:
            hitung_atk_to_atk = maxattack * H_state_prob[0][0] * E_state_prob[1][0]
            hitung_natk_to_atk = maxnonattack * H_state_prob[1][0] * E_state_prob[1][0]
            
            hitung_atk_to_natk = maxattack * H_state_prob[0][1] * E_state_prob[1][1]
            hitung_natk_to_natk = maxnonattack * H_state_prob[1][1] * E_state_prob[1][1]
            
            maxattack = max(hitung_atk_to_atk, hitung_natk_to_atk)
            maxnonattack = max(hitung_atk_to_natk, hitung_natk_to_natk)
        
            result_atk_prob.append(maxattack)
            result_natk_prob.append(maxnonattack)
        
        #state 3 GET 3xx 0
        elif testlogserverdata['Method'][a] == "GET" and testlogserverdata['HTTP Status Code'][a][0] == "3" and testlogserverdata['Error'][a] == 0:
            hitung_atk_to_atk = maxattack * H_state_prob[0][0] * E_state_prob[2][0]
            hitung_natk_to_atk = maxnonattack * H_state_prob[1][0] * E_state_prob[2][0]
            
            hitung_atk_to_natk = maxattack * H_state_prob[0][1] * E_state_prob[2][1]
            hitung_natk_to_natk = maxnonattack * H_state_prob[1][1] * E_state_prob[2][1]
            
            maxattack = max(hitung_atk_to_atk, hitung_natk_to_atk)
            maxnonattack = max(hitung_atk_to_natk, hitung_natk_to_natk)
        
            result_atk_prob.append(maxattack)
            result_natk_prob.append(maxnonattack)
            
        #state 4 GET 3xx 1
        elif testlogserverdata['Method'][a] == "GET" and testlogserverdata['HTTP Status Code'][a][0] == "3" and testlogserverdata['Error'][a] == 1:
            hitung_atk_to_atk = maxattack * H_state_prob[0][0] * E_state_prob[3][0]
            hitung_natk_to_atk = maxnonattack * H_state_prob[1][0] * E_state_prob[3][0]
            
            hitung_atk_to_natk = maxattack * H_state_prob[0][1] * E_state_prob[3][1]
            hitung_natk_to_natk = maxnonattack * H_state_prob[1][1] * E_state_prob[3][1]
            
            maxattack = max(hitung_atk_to_atk, hitung_natk_to_atk)
            maxnonattack = max(hitung_atk_to_natk, hitung_natk_to_natk)
        
            result_atk_prob.append(maxattack)
            result_natk_prob.append(maxnonattack)
            
        #state 5 GET 4xx 0
        elif testlogserverdata['Method'][a] == "GET" and testlogserverdata['HTTP Status Code'][a][0] == "4" and testlogserverdata['Error'][a] == 0:
            hitung_atk_to_atk = maxattack * H_state_prob[0][0] * E_state_prob[4][0]
            hitung_natk_to_atk = maxnonattack * H_state_prob[1][0] * E_state_prob[4][0]
            
            hitung_atk_to_natk = maxattack * H_state_prob[0][1] * E_state_prob[4][1]
            hitung_natk_to_natk = maxnonattack * H_state_prob[1][1] * E_state_prob[4][1]
            
            maxattack = max(hitung_atk_to_atk, hitung_natk_to_atk)
            maxnonattack = max(hitung_atk_to_natk, hitung_natk_to_natk)
        
            result_atk_prob.append(maxattack)
            result_natk_prob.append(maxnonattack)
            
        #state 6 GET 4xx 1
        elif testlogserverdata['Method'][a] == "GET" and testlogserverdata['HTTP Status Code'][a][0] == "4" and testlogserverdata['Error'][a] == 1:
            hitung_atk_to_atk = maxattack * H_state_prob[0][0] * E_state_prob[5][0]
            hitung_natk_to_atk = maxnonattack * H_state_prob[1][0] * E_state_prob[5][0]
            
            hitung_atk_to_natk = maxattack * H_state_prob[0][1] * E_state_prob[5][1]
            hitung_natk_to_natk = maxnonattack * H_state_prob[1][1] * E_state_prob[5][1]
            
            maxattack = max(hitung_atk_to_atk, hitung_natk_to_atk)
            maxnonattack = max(hitung_atk_to_natk, hitung_natk_to_natk)
        
            result_atk_prob.append(maxattack)
            result_natk_prob.append(maxnonattack)
            
        #state 7 GET 5xx 0
        elif testlogserverdata['Method'][a] == "GET" and testlogserverdata['HTTP Status Code'][a][0] == "5" and testlogserverdata['Error'][a] == 0:
            hitung_atk_to_atk = maxattack * H_state_prob[0][0] * E_state_prob[6][0]
            hitung_natk_to_atk = maxnonattack * H_state_prob[1][0] * E_state_prob[6][0]
            
            hitung_atk_to_natk = maxattack * H_state_prob[0][1] * E_state_prob[6][1]
            hitung_natk_to_natk = maxnonattack * H_state_prob[1][1] * E_state_prob[6][1]
            
            maxattack = max(hitung_atk_to_atk, hitung_natk_to_atk)
            maxnonattack = max(hitung_atk_to_natk, hitung_natk_to_natk)
        
            result_atk_prob.append(maxattack)
            result_natk_prob.append(maxnonattack)
            
        #state 8 GET 5xx 1
        elif testlogserverdata['Method'][a] == "GET" and testlogserverdata['HTTP Status Code'][a][0] == "5" and testlogserverdata['Error'][a] == 1:
            hitung_atk_to_atk = maxattack * H_state_prob[0][0] * E_state_prob[7][0]
            hitung_natk_to_atk = maxnonattack * H_state_prob[1][0] * E_state_prob[7][0]
            
            hitung_atk_to_natk = maxattack * H_state_prob[0][1] * E_state_prob[7][1]
            hitung_natk_to_natk = maxnonattack * H_state_prob[1][1] * E_state_prob[7][1]
            
            maxattack = max(hitung_atk_to_atk, hitung_natk_to_atk)
            maxnonattack = max(hitung_atk_to_natk, hitung_natk_to_natk)
        
            result_atk_prob.append(maxattack)
            result_natk_prob.append(maxnonattack)
            
        #state 9 POST 2xx 0
        elif testlogserverdata['Method'][a] == "POST" and testlogserverdata['HTTP Status Code'][a][0] == "2" and testlogserverdata['Error'][a] == 0:
            hitung_atk_to_atk = maxattack * H_state_prob[0][0] * E_state_prob[8][0]
            hitung_natk_to_atk = maxnonattack * H_state_prob[1][0] * E_state_prob[8][0]
            
            hitung_atk_to_natk = maxattack * H_state_prob[0][1] * E_state_prob[8][1]
            hitung_natk_to_natk = maxnonattack * H_state_prob[1][1] * E_state_prob[8][1]
            
            maxattack = max(hitung_atk_to_atk, hitung_natk_to_atk)
            maxnonattack = max(hitung_atk_to_natk, hitung_natk_to_natk)
        
            result_atk_prob.append(maxattack)
            result_natk_prob.append(maxnonattack)
        
        #state 10
        elif testlogserverdata['Method'][a] == "POST" and testlogserverdata['HTTP Status Code'][a][0] == "2" and testlogserverdata['Error'][a] == 1:
            hitung_atk_to_atk = maxattack * H_state_prob[0][0] * E_state_prob[9][0]
            hitung_natk_to_atk = maxnonattack * H_state_prob[1][0] * E_state_prob[9][0]
            
            hitung_atk_to_natk = maxattack * H_state_prob[0][1] * E_state_prob[9][1]
            hitung_natk_to_natk = maxnonattack * H_state_prob[1][1] * E_state_prob[9][1]
            
            maxattack = max(hitung_atk_to_atk, hitung_natk_to_atk)
            maxnonattack = max(hitung_atk_to_natk, hitung_natk_to_natk)
        
            result_atk_prob.append(maxattack)
            result_natk_prob.append(maxnonattack)
            
        #state 11
        elif testlogserverdata['Method'][a] == "POST" and testlogserverdata['HTTP Status Code'][a][0] == "3" and testlogserverdata['Error'][a] == 0:
            hitung_atk_to_atk = maxattack * H_state_prob[0][0] * E_state_prob[10][0]
            hitung_natk_to_atk = maxnonattack * H_state_prob[1][0] * E_state_prob[10][0]
            
            hitung_atk_to_natk = maxattack * H_state_prob[0][1] * E_state_prob[10][1]
            hitung_natk_to_natk = maxnonattack * H_state_prob[1][1] * E_state_prob[10][1]
            
            maxattack = max(hitung_atk_to_atk, hitung_natk_to_atk)
            maxnonattack = max(hitung_atk_to_natk, hitung_natk_to_natk)
        
            result_atk_prob.append(maxattack)
            result_natk_prob.append(maxnonattack)
            
        #state 12
        elif testlogserverdata['Method'][a] == "POST" and testlogserverdata['HTTP Status Code'][a][0] == "3" and testlogserverdata['Error'][a] == 1:
            hitung_atk_to_atk = maxattack * H_state_prob[0][0] * E_state_prob[11][0]
            hitung_natk_to_atk = maxnonattack * H_state_prob[1][0] * E_state_prob[11][0]
            
            hitung_atk_to_natk = maxattack * H_state_prob[0][1] * E_state_prob[11][1]
            hitung_natk_to_natk = maxnonattack * H_state_prob[1][1] * E_state_prob[11][1]
            
            maxattack = max(hitung_atk_to_atk, hitung_natk_to_atk)
            maxnonattack = max(hitung_atk_to_natk, hitung_natk_to_natk)
        
            result_atk_prob.append(maxattack)
            result_natk_prob.append(maxnonattack)
            
        #state 13
        elif testlogserverdata['Method'][a] == "POST" and testlogserverdata['HTTP Status Code'][a][0] == "4" and testlogserverdata['Error'][a] == 0:
            hitung_atk_to_atk = maxattack * H_state_prob[0][0] * E_state_prob[12][0]
            hitung_natk_to_atk = maxnonattack * H_state_prob[1][0] * E_state_prob[12][0]
            
            hitung_atk_to_natk = maxattack * H_state_prob[0][1] * E_state_prob[12][1]
            hitung_natk_to_natk = maxnonattack * H_state_prob[1][1] * E_state_prob[12][1]
            
            maxattack = max(hitung_atk_to_atk, hitung_natk_to_atk)
            maxnonattack = max(hitung_atk_to_natk, hitung_natk_to_natk)
        
            result_atk_prob.append(maxattack)
            result_natk_prob.append(maxnonattack)
            
        #state 14
        elif testlogserverdata['Method'][a] == "POST" and testlogserverdata['HTTP Status Code'][a][0] == "4" and testlogserverdata['Error'][a] == 1:
            hitung_atk_to_atk = maxattack * H_state_prob[0][0] * E_state_prob[13][0]
            hitung_natk_to_atk = maxnonattack * H_state_prob[1][0] * E_state_prob[13][0]
            
            hitung_atk_to_natk = maxattack * H_state_prob[0][1] * E_state_prob[13][1]
            hitung_natk_to_natk = maxnonattack * H_state_prob[1][1] * E_state_prob[13][1]
            
            maxattack = max(hitung_atk_to_atk, hitung_natk_to_atk)
            maxnonattack = max(hitung_atk_to_natk, hitung_natk_to_natk)
        
            result_atk_prob.append(maxattack)
            result_natk_prob.append(maxnonattack)
            
        #state 15
        elif testlogserverdata['Method'][a] == "POST" and testlogserverdata['HTTP Status Code'][a][0] == "5" and testlogserverdata['Error'][a] == 0:
            hitung_atk_to_atk = maxattack * H_state_prob[0][0] * E_state_prob[14][0]
            hitung_natk_to_atk = maxnonattack * H_state_prob[1][0] * E_state_prob[14][0]
            
            hitung_atk_to_natk = maxattack * H_state_prob[0][1] * E_state_prob[14][1]
            hitung_natk_to_natk = maxnonattack * H_state_prob[1][1] * E_state_prob[14][1]
            
            maxattack = max(hitung_atk_to_atk, hitung_natk_to_atk)
            maxnonattack = max(hitung_atk_to_natk, hitung_natk_to_natk)
        
            result_atk_prob.append(maxattack)
            result_natk_prob.append(maxnonattack)
            
        #state 16
        elif testlogserverdata['Method'][a] == "POST" and testlogserverdata['HTTP Status Code'][a][0] == "5" and testlogserverdata['Error'][a] == 1:
            hitung_atk_to_atk = maxattack * H_state_prob[0][0] * E_state_prob[15][0]
            hitung_natk_to_atk = maxnonattack * H_state_prob[1][0] * E_state_prob[15][0]
            
            hitung_atk_to_natk = maxattack * H_state_prob[0][1] * E_state_prob[15][1]
            hitung_natk_to_natk = maxnonattack * H_state_prob[1][1] * E_state_prob[15][1]
            
            maxattack = max(hitung_atk_to_atk, hitung_natk_to_atk)
            maxnonattack = max(hitung_atk_to_natk, hitung_natk_to_natk)
        
            result_atk_prob.append(maxattack)
            result_natk_prob.append(maxnonattack)
        else:
            print("error di index", a)
    
    else:
        print("error di index", a)
        
print("Viterbi clear")
        
for atk, natk in zip(result_atk_prob, result_natk_prob):
    if atk > natk:
        testlogserverclasspredict = testlogserverclasspredict.append({'Class': 'Attack'}, ignore_index=True)
    else:
        testlogserverclasspredict = testlogserverclasspredict.append({'Class': 'Non Attack'}, ignore_index=True)        
        
print("Selesai testing")

print("Confiusion Matrix\n")
print(confusion_matrix(testlogserverclass, testlogserverclasspredict))
print("\nAkurasi nya ialah", accuracy_score(testlogserverclass, testlogserverclasspredict), "\n")

testlogserver['Class predict'] = testlogserverclasspredict.copy()
testlogserver = testlogserver.sort_values(by=['Timestamp'], ascending=True)
testlogserver = testlogserver.reset_index(drop=True)
#testlogserver.to_csv('/media/root/New Volume/BelajarBung/Kuliah/Skripsi/coding/logstash_config/data/1 Data Clean/csv file/predict/webserserverlogpredict_test30%.csv')

timeend = datetime.datetime.now()
print("time end: ",timeend)
print("HMM duration: ", timeend-timestart)