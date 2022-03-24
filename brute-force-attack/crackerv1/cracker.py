import string

seed = list(string.ascii_lowercase + string.ascii_uppercase + " " + "-")
secret = input("Enter your password:")
guess = ""

while (guess != secret):
    for i in range(len(secret)):
        for letter in seed:
            if letter == secret[i]:
                guess += letter
                break
print("Your password is",guess)
