from sys import argv

script, filename = argv

txt = open(filename)  #cs692_hw1.txt

'''
Lists for keeping track of 
open transactions and their timestamps
'''
openTransact = []
closeTransact = []
timeOftransact = []
timeOfresponse = []

'''
dummy variables for finding 
the desired values from the text file.
'''
i = 0
a = 0
b = 0
read_ID = 0
u = 0
v = 0
p = 0
q = 0

'''
Reading the Transaction ID,
Timestamp, and the Protocol
'''
i = len('0x') 
j = len('Time')
k = len('Protocol')

'''
Function for subtracting the timestamps
'''

def dnsdelay(queryTime, responseTime): 
    
    queryTime = float(queryTime)
    responseTime = float(responseTime)
    try:
        timeDiff = responseTime - queryTime
    except ValueError,e:
        print "error",e,"on line",line
    return(timeDiff)

print('<report>')
print('<description>DNS delays</description>')

for line in txt:
    
    x = 0
    
    while x < len(line):
        if line[x:x+k] == 'Protocol':
            p = x
            q = x + 3
        if line[x:x+j] == 'Time':
            u = x
            v = x + 8
        if line[x:x+i] == '0x':
            a = x
            b = a + 6
        x = x + 1

    if line[p:q] == 'DNS':
        if line[a:b] in (openTransact and closeTransact):
            timeOftransact.remove(timeOftransact[openTransact.index(line[a:b])])
            timeOfresponse.remove(timeOfresponse[closeTransact.index(line[a:b])])
            openTransact.remove(line[a:b])
            closeTransact.remove(line[a:b])
        if line[a:b] not in openTransact:
            openTransact.append(line[a:b])
            timeOftransact.append(line[u:v])
        else:
            delay = dnsdelay(timeOftransact[openTransact.index(line[a:b])], line[u:v])
            print('<delay>'+str(delay)+'</delay>')
            closeTransact.append(line[a:b])
            timeOfresponse.append(line[u:v])
        read_ID = 0

print('</report>')
    






