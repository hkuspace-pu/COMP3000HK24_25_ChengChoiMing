# COMP3000HK24_25_ChengChoiMing

Web Vulnerability Scanner

# The Goal:

To goal for this tools is for you to scan a website is there any vulnerability. It is included Nikto and Skipfish. You can also enable the ZAP HUD Function to have testing with your website.
!! Please run this tool in Kali linux !!

# Installation Guide:

Please download MairaDB SQL in your computer, then setup the database for the Tool. You can see the host, data name, table name, and username password
You can follow below step
Here is the command for installing MariaDB

# For Kali linux

sudo apt-get update
sudo apt-get install mariadb-server
sudo systemctl start mariadb
sudo systemctl enable mariadb

Make sure the DB is online you can use
sudo systemctl status mariadb

Once you know the DB is online then you can start to create the DB for the tool

First:
-- Login --
sudo mysql -u root -p

-- Create Database --
CREATE DATABASE project
CHARACTER SET utf8mb4
COLLATE utf8mb4_general_ci;

-- Create User --
CREATE USER 'nikto'@'localhost' IDENTIFIED BY 'projectuse';

-- Grant Privileges --
GRANT ALL PRIVILEGES ON project.\* TO 'nikto'@'localhost';
FLUSH PRIVILEGES;

Once the database is created then you can create table for the tool

-- Select the DataBase --
USE project;

-- Nikto Table --
CREATE TABLE nikto (
id INT AUTO_INCREMENT PRIMARY KEY,
date DATE,
content TEXT,
cmd VARCHAR(255)
);

-- Skipfish Table --
CREATE TABLE skipfish (
id INT AUTO_INCREMENT PRIMARY KEY,
date DATE,
cmd TEXT,
path TEXT
);

For install Python connect to the Tool
pip install mysql-connector-python
pip install matplotlib pandas tk fpdf selenium psutil requests

# Import function install

pip install matplotlib pandas requests mysql-connector-python beautifulsoup4 fpdf numpy selenium webdriver-manager psutil

# Core dependencies

sudo pip install matplotlib pandas numpy requests psutil

# PDF generation

sudo pip install fpdf

# Web scraping

sudo pip install beautifulsoup4

# Database connectivity

sudo pip install mysql-connector-python

# Browser automation

sudo pip install selenium webdriver-manager

# GUI components

sudo apt install python3-tk

# Browser and drivers

sudo apt install firefox-esr geckodriver

# Database server

sudo apt install mariadb-server

For testing use DVWA you can follow below youtube link to install.
https://youtu.be/Yzksa_WjnY0?si=JcqOVJAGyway9MlX

For test use AI you can follow below youtube link to install.
https://youtu.be/nt1SzojVy38?si=GRxObTS_0z4QI7Fb

Download the Ollama
https://ollama.com/download/windows
