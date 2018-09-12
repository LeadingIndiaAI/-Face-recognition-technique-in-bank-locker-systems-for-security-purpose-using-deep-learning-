# Face-Recognition-for-providing-security-using-Deep-learning
This is a Project on maintaining Security in Bank Lockers or at any system using Face Recognition which is developed using Convolutional Neural Network in Deep Learning.

------------------------------------------------------------------------------------------------------------------------------------------

Download these files and create the virtual environment for the project.
Then in activated virtual environment install all the requirememts as mentioned in requirement.txt file.

------------------------------------------------------------------------------------------------------------------------------------------

Manually add about 500 images not containing human faces at all like that of mountains, flowers, and many other of these types in application>database>images>00not folder.
Then for connecting the system with database install mysql and make migrations for the views.models in django.

------------------------------------------------------------------------------------------------------------------------------------------

Now create the superuser as an first admin to add an entry of the auth table in django. While other admins can be created from within the Web App.
Now run the server after going in that application folder.

------------------------------------------------------------------------------------------------------------------------------------------

Now on Admin login page use superadmin email and password to log in as an Admin.
After clicking to add user option the dataset will be taken and then model will start training at that time after dataset being taken.

------------------------------------------------------------------------------------------------------------------------------------------

On User Login page, after entering Locker number the User will be able to login with proper recognition of their face.

------------------------------------------------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------------------------------------------------------

Related Poster of the Project : https://drive.google.com/open?id=1GgI54KyTBUWOCNFW-SLxwlLbZWOdZakf

------------------------------------------------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------------------------------------------------------

#ScreenShots of the Web Application

SS-1 It is the User login page where user has to put the locker number which is assigned to the user.
![](ScreenShots/1.png)

SS-2 It is the User Dashboard that welcomes the User after proper face recognition of the user Face.
![](ScreenShots/2.png)

SS-3It is the Admin login page where only valid Admin can Login with authorised Email and Password.
![](ScreenShots/3.png)

SS-4 It is the Admin Dashboard which possess the detailed information of all the Login Activity.
![](ScreenShots/4.png)

SS-5 It consists of JQuaryDataTable with is Showing all the Details of all the Admins and giving various options to the Admins.
![](ScreenShots/5.png)

SS-6 It is the Webpage showing the requirements to add a New Admin.
![](ScreenShots/6.png)

SS-7 It consists of JQuaryDataTable with is Showing all the Details of all the Users and giving various options to amend the credentials 
of the User to the Admin.
![](ScreenShots/7.png)

SS-8 It is a Webpage on which Admin has to assign Locker number and username to the User for providing account of the User.
![](ScreenShots/8.png)

SS-9 To train the model, first Collect the DataSet of the person by Clicking the COLEECT DATASET.
![](ScreenShots/9.png)

SS-10 Then to train the Model click on TRAIN MODEL.
![](ScreenShots/10.png)
