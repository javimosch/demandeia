#!/bin/bash

# Prompt for email
read -p "Enter user email: " email

# Prompt for password (hidden input)
read -s -p "Enter new password: " password
echo

# Prompt for password confirmation
read -s -p "Confirm new password: " password_confirm
echo

# Check if passwords match
if [ "$password" != "$password_confirm" ]; then
    echo "Passwords do not match. Please try again."
    exit 1
fi

# Call the Node.js script
node ./scripts/changeUserPwd.js "$email" "$password"

# Check the exit status of the Node.js script
if [ $? -eq 0 ]; then
    echo "Password change successful."
else
    echo "Password change failed. Please check the error message above."
fi
