from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.service import Service
import time

# Set up the Service with the path to geckodriver
service = Service("C:\\Users\\HP\\Downloads\\chromedriver.exe")

# Initialize the WebDriver with the service
driver = webdriver.Firefox(service=service)
driver.maximize_window()

try:
    # Step: Open the login page
    print("Opening the login page...")
    driver.get("http://127.0.0.1:8000/login/")
    time.sleep(2)

    # Step: Enter username and password
    print("Entering username and password...")
    driver.find_element(By.ID, "email").send_keys("devikaprasad2025@mca.ajce.in")
    driver.find_element(By.ID, "password").send_keys("Devika@2023")

    # Step: Click on the login button
    print("Clicking on the login button...")
    driver.find_element(By.ID, "login").click()

    # Step: Verify if login was successful and user is on the home page
    time.sleep(2)
    if driver.find_element(By.ID, "button").is_displayed() and driver.find_element(By.ID, "logout").is_displayed():
        print("Login successful and user is on the home page")
    else:
        print("Login failed or not navigated to the home page")

finally:
    # Close the browser
    time.sleep(2)
    driver.quit()
