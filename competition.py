import pandas as pd
import numpy as np

print("hello world")

list_of_train = ['number_of_slot','number_of_day','number_of_weekday','number_of_hour']
list_of_target = ['stream1','stream2','stream3','stream4','bandwidth_available_OTT']

data = pd.read_csv("train_data.csv")

#lst_x = []
#for i in range(len(data)):
 #   lst_x.append([data.number_of_slot[i], data.number_of_day[i], data.number_of_weekday[i], data.number_of_hour[i]])

#lst_y = []
#for i in range(len(data)):
 #   lst_y.append([round(data.stream1[i],6) , round(data.stream2[i], 6), round(data.stream3[i], 6),  round(data.stream4[i], 6), round(data.stream5[i], 6), round(data.bandwidth_available_OTT[i], 6)])

x = data[list_of_train]

y = data[list_of_target]

from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor

#clf = RandomForestClassifier()

reg = RandomForestRegressor()

x_d = pd.read_csv("test_data.csv")

#lst_test_x = []
#for i in range(len(x_d)):
 #   lst_test_x.append([x_d.number_of_slot[i], x_d.number_of_day[i], x_d.number_of_weekday[i], x_d.number_of_hour[i]])

test_x = x_d[list_of_train]

# fit the model to the training data (learn the coefficients)
reg.fit(x, y)

# make predictions on the testing set
y_pred = reg.predict(test_x)

print(len(y_pred))
for i in range(len(y_pred)):
    print(y_pred[i])