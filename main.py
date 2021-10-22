import sys
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *


class DynamicWidget:

    def __init__(self, type_of, layout, layout_args, text=""):
        self.text = text
        self.type_of = type_of
        self.widget = self.type_of(self.text)
        self.layout = layout
        self.layout_args = layout_args
        self.to_link = None
        self.refresh()

    def refresh(self):
        self.clear()
        self.widget = self.type_of(self.text)
        self.layout.addWidget(self.widget, *self.layout_args)

    def clear(self):
        self.widget.setParent(None)

    def set_text(self, text):
        self.text = text
        self.refresh()

    def get_text(self):
        if self.type_of == QLineEdit:
            return self.widget.text()
        if self.type_of == QPlainTextEdit:
            return self.widget.toPlainText()
        else:
            return self.text

    def set_type(self, type_of):
        self.type_of = type_of
        self.refresh()

    def button_refresh(self):
        self.clear()
        self.widget = self.type_of(self.text)
        self.widget.clicked.connect(self.to_link)
        self.layout.addWidget(self.widget, *self.layout_args)

    def set_button_connect(self, to_link):
        self.to_link = to_link
        self.refresh = self.button_refresh

    def center(self):
        self.widget.setAlignment(Qt.AlignCenter)


class SolutionWindow(QScrollArea):

    def __init__(self, title, parent=None):

        super().__init__(parent)
        self.setWindowTitle(title)
        self.main_widget = QWidget()
        self.main_layout = QVBoxLayout(self.main_widget)
        self.main_layout.setAlignment(Qt.AlignTop)
        self.setMinimumWidth(400)
        self.setWidget(self.main_widget)
        self.setWidgetResizable(True)

    def add_text(self, text):
        widget = QLabel(text)
        widget.setTextInteractionFlags(Qt.TextSelectableByMouse)
        widget.setAlignment(Qt.AlignCenter)
        widget.setWordWrap(True)
        self.main_layout.addWidget(widget)


class Window(QMainWindow):

    def __init__(self, parent=None):

        super().__init__(parent)
        self.setWindowTitle('MATH 5248 Midterm Project')
        self.main_widget = QWidget(self)
        self.setCentralWidget(self.main_widget)
        self.resize(800, 600)

        # create menus
        menu_bar = self.menuBar()
        cipher_menu = menu_bar.addMenu("&Cipher")
        mode_menu = menu_bar.addMenu('&Mode')
        help_menu = menu_bar.addMenu('&Help')
        self.blank_icon = QIcon('images\\blank.png')
        self.check_icon = QIcon('images\\check.png')

        # populate menus
        # caesar cipher
        self.caesar_action = QAction(self)
        self.caesar_action.setText('&Caesar')
        self.caesar_action.triggered.connect(self.set_cipher_caesar)
        cipher_menu.addAction(self.caesar_action)
        # affine cipher
        self.affine_action = QAction(self)
        self.affine_action.setText('&Affine')
        self.affine_action.triggered.connect(self.set_cipher_affine)
        cipher_menu.addAction(self.affine_action)
        # vigenere cipher
        # self.vigenere_action = QAction(self)
        # self.vigenere_action.setText('&Vigenere')
        # self.vigenere_action.triggered.connect(self.set_cipher_vigenere)
        # cipher_menu.addAction(self.vigenere_action)
        # encrypt
        self.encrypt_action = QAction(self)
        self.encrypt_action.setText('&Encrypt')
        self.encrypt_action.triggered.connect(self.set_mode_encrypt)
        mode_menu.addAction(self.encrypt_action)
        # decrypt
        self.decrypt_action = QAction(self)
        self.decrypt_action.setText('&Decrypt')
        self.decrypt_action.triggered.connect(self.set_mode_decrypt)
        mode_menu.addAction(self.decrypt_action)
        # known plaintext attack
        self.known_plaintext_action = QAction(self)
        self.known_plaintext_action.setText('&Known Plaintext Attack')
        self.known_plaintext_action.triggered.connect(self.set_mode_known_plaintext)
        mode_menu.addAction(self.known_plaintext_action)
        # ciphertext only attack
        self.ciphertext_only_action = QAction(self)
        self.ciphertext_only_action.setText('&Ciphertext Only Attack')
        self.ciphertext_only_action.triggered.connect(self.set_mode_ciphertext_only)
        mode_menu.addAction(self.ciphertext_only_action)
        # about
        self.about_action = QAction(self)
        self.about_action.setText('&About')
        self.about_action.triggered.connect(self.help_about)
        help_menu.addAction(self.about_action)
        self.cipher_actions = [self.caesar_action, self.affine_action]#, self.vigenere_action]
        self.mode_actions = [self.encrypt_action, self.decrypt_action,
                             self.known_plaintext_action, self.ciphertext_only_action]
        self.cipher = ""
        self.mode = ""

        # generate layout
        self.main_layout = QGridLayout()
        self.title_text = DynamicWidget(QLabel, self.main_layout, (0, 0))
        self.title_text.center()
        self.example_button = DynamicWidget(QPushButton, self.main_layout, (0, 1))
        self.label_1 = DynamicWidget(QLabel, self.main_layout, (1, 0))
        self.text_1 = DynamicWidget(QLineEdit, self.main_layout, (1, 1))
        self.label_2 = DynamicWidget(QLabel, self.main_layout, (2, 0))
        self.text_2 = DynamicWidget(QPlainTextEdit, self.main_layout, (2, 1))
        self.go_button = DynamicWidget(QPushButton, self.main_layout, (3, 0))
        self.go_button.set_button_connect(self.do_it)
        self.example_button.set_button_connect(self.load_example)
        self.main_widget.setLayout(self.main_layout)
        self.example_button.set_text('Load Example:')

        # other variables
        self.solutions = []
        self.alphabet = 'abcdefghijklmnopqrstuvwxyz'
        self.numbers = '0123456789'
        file = open("data\\dictionary.txt")
        self.dictionary = file.read().split('\n')
        file.close()
        file = open("data\\common words.txt")
        self.common = file.read().split('\n')[0:10000]
        file.close()
        file = open("data/explaination.txt")
        self.help = file.read()
        file.close()
        self.bad_key = 'Invalid key, please try again'
        self.bad_plaintext = 'Invalid plaintext/ciphertext combination, please try again'
        self.bad_ciphertext = 'Cipher text could not be decrypted, please try again'

        # open with default mode
        self.set_cipher_caesar()
        self.set_mode_encrypt()

    def set_check_icon(self, actions, index):
        for f in range(len(actions)):
            if f == index:
                actions[f].setIcon(self.check_icon)
            else:
                actions[f].setIcon(self.blank_icon)

    def set_cipher_caesar(self):
        # set status
        self.set_check_icon(self.cipher_actions, 0)
        self.title_text.set_text('Caesar')

    def set_cipher_affine(self):
        # set status
        self.set_check_icon(self.cipher_actions, 1)
        self.title_text.set_text('Affine')

    def set_cipher_vigenere(self):
        # set status
        self.set_check_icon(self.cipher_actions, 2)
        self.title_text.set_text('Vigenere')

    def set_mode_encrypt(self):
        # set status
        self.set_check_icon(self.mode_actions, 0)
        self.mode = "Encryption"
        # prepare input fields
        self.label_1.set_text('Input Key:')
        self.text_1.set_type(QLineEdit)
        self.label_2.set_text('Input Plaintext:')
        self.go_button.set_text('Encrypt')

    def set_mode_decrypt(self):
        # set status
        self.set_check_icon(self.mode_actions, 1)
        self.mode = 'Decryption'
        # prepare input fields
        self.label_1.set_text('Input Key:')
        self.text_1.set_type(QLineEdit)
        self.label_2.set_text('Input Ciphertext:')
        self.go_button.set_text('Decrypt')

    def set_mode_known_plaintext(self):
        # set status
        self.set_check_icon(self.mode_actions, 2)
        self.mode = 'Plaintext Attack'
        # prepare input fields
        self.label_1.set_text('Input Plaintext:')
        self.text_1.set_type(QPlainTextEdit)
        self.label_2.set_text('Input Ciphertext:')
        self.go_button.set_text('Find Key')

    def set_mode_ciphertext_only(self):
        # set status
        self.set_check_icon(self.mode_actions, 3)
        self.mode = 'Ciphertext Attack'
        # prepare input fields
        self.label_1.clear()
        self.text_1.clear()
        self.label_2.set_text('Input Ciphertext:')
        self.go_button.set_text('Find Plaintext and Key')

    def load_example(self):
        if self.title_text.get_text() == 'Caesar':
            if self.mode == 'Encryption':
                self.text_1.set_text('F')
                self.text_2.set_text('A dog ate my homework')
            elif self.mode == 'Decryption':
                self.text_1.set_text('X')
                self.text_2.set_text('F dlq xk X fk jxqe')
            elif self.mode == 'Plaintext Attack':
                self.text_1.set_text('straightforward')
                self.text_2.set_text('nomvdbcoajmrvmy')
            elif self.mode == 'Ciphertext Attack':
                self.text_2.set_text('Trvjri nrj re rttfdgczjyvu rlkyfi reu yzjkfizre rj nvcc rj r jkrkvjdre')
        if self.title_text.get_text() == 'Affine':
            if self.mode == 'Encryption':
                self.text_1.set_text('7, 11')
                self.text_2.set_text('I just drank a big slurpee')
            elif self.mode == 'Decryption':
                self.text_1.set_text('17, 21')
                self.text_2.set_text('Fvgdk czy yzaabit yzdjp')
            elif self.mode == 'Plaintext Attack':
                self.text_1.set_text('A little bit trickier')
                self.text_2.set_text('M vcllvu bcl lhcqgcuh')
            elif self.mode == 'Ciphertext Attack':
                self.text_2.set_text('Yut jccdwt bdoutg dp j yrot fc nfwfjeoujstydb phspydyhydfw bdoutg')

    def do_it(self):
        self.solutions.append(SolutionWindow(self.title_text.get_text()+' '+self.mode))
        if self.title_text.get_text() == 'Caesar':
            if self.mode == 'Encryption':
                key = self.text_1.get_text()
                plaintext = self.text_2.get_text()
                find_key = get_chunks(key, self.alphabet)
                if not find_key:
                    find_key = get_chunks(key, self.numbers)
                    if not find_key:
                        self.solutions[-1].add_text(self.bad_key)
                        self.solutions[-1].show()
                        return None
                    find_key[0] = self.alphabet[int(find_key[0]) % len(self.alphabet)]
                found_key = find_key[0][0]
                key_num = self.alphabet.index(found_key)
                lets = find_elems(plaintext, self.alphabet)
                plain_nums = [self.alphabet.index(f) for f in lets]
                encrypted_nums = [(f+key_num) % len(self.alphabet) for f in plain_nums]
                encrypted_lets = [self.alphabet[f] for f in encrypted_nums]
                encrypted_text = insert_elems(plaintext, encrypted_lets, self.alphabet)
                self.solutions[-1].add_text('Our key is')
                self.solutions[-1].add_text(found_key.upper() + ', or ' + str(key_num))
                self.solutions[-1].add_text('Our text as numbers is')
                self.solutions[-1].add_text(' '.join(str(f) for f in plain_nums))
                self.solutions[-1].add_text('We encrypt this with the formula c ≡ p + k (mod 26) '
                                            'where p is a plaintext letter, k is the key, and c is encrypted letter.')
                self.solutions[-1].add_text('This gives us the following encrypted values')
                self.solutions[-1].add_text(' '.join(str(f) for f in encrypted_nums))
                self.solutions[-1].add_text('Returning the numbers to text, we obtain the final encrypted text:')
                self.solutions[-1].add_text('"' + encrypted_text + '"')
            elif self.mode == 'Decryption':
                key = self.text_1.get_text()
                ciphertext = self.text_2.get_text()
                find_key = get_chunks(key, self.alphabet)
                if not find_key:
                    find_key = get_chunks(key, self.numbers)
                    if not find_key:
                        self.solutions[-1].add_text(self.bad_key)
                        self.solutions[-1].show()
                        return None
                    find_key[0] = self.alphabet[int(find_key[0]) % len(self.alphabet)]
                found_key = find_key[0][0]
                key_num = self.alphabet.index(found_key)
                lets = find_elems(ciphertext, self.alphabet)
                cipher_nums = [self.alphabet.index(f) for f in lets]
                decrypted_nums = [(f-key_num) % len(self.alphabet) for f in cipher_nums]
                decrypted_lets = [self.alphabet[f] for f in decrypted_nums]
                decrypted_text = insert_elems(ciphertext, decrypted_lets, self.alphabet)
                self.solutions[-1].add_text('Our key is')
                self.solutions[-1].add_text(found_key.upper() + ', or ' + str(key_num))
                self.solutions[-1].add_text('Our text as numbers is')
                self.solutions[-1].add_text(' '.join(str(f) for f in cipher_nums))
                self.solutions[-1].add_text('We decrypt this with the formula p ≡ c - k (mod 26) '
                                            'where p is a plaintext letter, k is the key, and c is encrypted letter.')
                self.solutions[-1].add_text('This gives us the following decrypted values')
                self.solutions[-1].add_text(' '.join(str(f) for f in decrypted_nums))
                self.solutions[-1].add_text('Returning the numbers to text, we obtain the final decrypted text:')
                self.solutions[-1].add_text('"' + decrypted_text + '"')
            elif self.mode == 'Plaintext Attack':
                plaintext = self.text_1.get_text()
                ciphertext = self.text_2.get_text()
                plain_str = find_elems(plaintext, self.alphabet)
                cipher_str = find_elems(ciphertext, self.alphabet)
                if not plain_str or not cipher_str or len(plain_str) != len(cipher_str):
                    self.solutions[-1].add_text(self.bad_plaintext)
                    self.solutions[-1].show()
                    return None
                keys = []
                for f in range(len(plain_str)):
                    keys.append((self.alphabet.index(cipher_str[f]) - self.alphabet.index(plain_str[f])) % 26)
                key = max(set(keys), key=keys.count)
                self.solutions[-1].add_text('We find the key with the formula k ≡ c - p (mod 26) '
                                            'where p is a plaintext letter, k is the key, and c is encrypted letter.')
                self.solutions[-1].add_text('Applying this to the entered text, we find the key to be')
                self.solutions[-1].add_text(self.alphabet[key].upper() + ', or ' + str(key))
            elif self.mode == 'Ciphertext Attack':
                ciphertext = self.text_2.get_text()
                cipher_str = find_elems(ciphertext, self.alphabet)
                scores = []
                for f in range(len(self.alphabet)):
                    scores.append(0)
                    temp_lets = ''.join(self.alphabet[(self.alphabet.index(g) - f) % 26] for g in cipher_str)
                    for d in self.dictionary:
                        if d in temp_lets:
                            scores[-1] += 1
                key = scores.index(max(scores))
                cipher_nums = [self.alphabet.index(f) for f in cipher_str]
                decrypted_nums = [(f-key) % len(self.alphabet) for f in cipher_nums]
                decrypted_lets = [self.alphabet[f] for f in decrypted_nums]
                decrypted_text = insert_elems(ciphertext, decrypted_lets, self.alphabet)
                self.solutions[-1].add_text('We find the key via brute force. We try all possible keys and '
                                            'see which one produces text that makes sense.')
                self.solutions[-1].add_text('We find the key to be')
                self.solutions[-1].add_text(self.alphabet[key].upper() + ', or ' + str(key))
                self.solutions[-1].add_text('And the decrypted text to be')
                self.solutions[-1].add_text('"' + decrypted_text + '"')
        if self.title_text.get_text() == 'Affine':
            if self.mode == 'Encryption':
                key = self.text_1.get_text()
                plaintext = self.text_2.get_text()
                find_key = get_chunks(key, self.numbers)
                print(find_key)
                if len(find_key) != 2:
                    self.solutions[-1].add_text(self.bad_key)
                    self.solutions[-1].show()
                    return None
                found_key = (int(find_key[0]) % 26, int(find_key[1]) % 26)
                a, b = found_key
                if gcd(a, len(self.alphabet)) != 1:
                    self.solutions[-1].add_text(self.bad_key)
                    self.solutions[-1].show()
                    return None
                lets = find_elems(plaintext, self.alphabet)
                plain_nums = [self.alphabet.index(f) for f in lets]
                encrypted_nums = [(a*f + b) % len(self.alphabet) for f in plain_nums]
                encrypted_lets = [self.alphabet[f] for f in encrypted_nums]
                encrypted_text = insert_elems(plaintext, encrypted_lets, self.alphabet)
                self.solutions[-1].add_text('Our key is')
                self.solutions[-1].add_text('(%s, %s)' % (a, b))
                self.solutions[-1].add_text('Our text as numbers is')
                self.solutions[-1].add_text(' '.join(str(f) for f in plain_nums))
                self.solutions[-1].add_text('We encrypt this with the formula c ≡ a·p + b (mod 26) where '
                                            'p is a plaintext letter, (a, b) is the key, and c is encrypted letter.')
                self.solutions[-1].add_text('This gives us the following encrypted values')
                self.solutions[-1].add_text(' '.join(str(f) for f in encrypted_nums))
                self.solutions[-1].add_text('Returning the numbers to text, we obtain the final encrypted text:')
                self.solutions[-1].add_text('"' + encrypted_text + '"')
            elif self.mode == 'Decryption':
                key = self.text_1.get_text()
                ciphertext = self.text_2.get_text()
                find_key = get_chunks(key, self.numbers)
                print(find_key)
                if len(find_key) != 2:
                    self.solutions[-1].add_text(self.bad_key)
                    self.solutions[-1].show()
                    return None
                found_key = (int(find_key[0]) % 26, int(find_key[1]) % 26)
                a, b = found_key
                if gcd(a, len(self.alphabet)) != 1:
                    self.solutions[-1].add_text(self.bad_key)
                    self.solutions[-1].show()
                    return None
                a_inv = pow(a, -1, len(self.alphabet))
                lets = find_elems(ciphertext, self.alphabet)
                cipher_nums = [self.alphabet.index(f) for f in lets]
                decrypted_nums = [(a_inv*(f-b)) % len(self.alphabet) for f in cipher_nums]
                decrypted_lets = [self.alphabet[f] for f in decrypted_nums]
                decrypted_text = insert_elems(ciphertext, decrypted_lets, self.alphabet)
                self.solutions[-1].add_text('Our key is')
                self.solutions[-1].add_text('(%s, %s)' % (a, b))
                self.solutions[-1].add_text('The modular inverse of %s (mod 26) is %s.' % (a, a_inv))
                self.solutions[-1].add_text('Our text as numbers is')
                self.solutions[-1].add_text(' '.join(str(f) for f in cipher_nums))
                self.solutions[-1].add_text('We decrypt this with the formula p ≡ a_inv·(c-b) (mod 26) where p is a '
                                            'plaintext letter, (a, b) is the key, and c is encrypted letter, '
                                            'and a_inv is the inverse of a modulo 26.')
                self.solutions[-1].add_text('This gives us the following decrypted values')
                self.solutions[-1].add_text(' '.join(str(f) for f in decrypted_nums))
                self.solutions[-1].add_text('Returning the numbers to text, we obtain the final decrypted text:')
                self.solutions[-1].add_text('"' + decrypted_text + '"')
            elif self.mode == 'Plaintext Attack':
                plaintext = self.text_1.get_text()
                ciphertext = self.text_2.get_text()
                plain_str = find_elems(plaintext, self.alphabet)
                cipher_str = find_elems(ciphertext, self.alphabet)
                if not plain_str or not cipher_str or len(plain_str) != len(cipher_str) or uniform(plain_str):
                    print(uniform(plain_str))
                    self.solutions[-1].add_text(self.bad_plaintext)
                    self.solutions[-1].show()
                    return None
                p1 = self.alphabet.index(plain_str[0])
                p2 = self.alphabet.index(plain_str[1])
                i = 1
                while p1 == p2:
                    i += 1
                    p2 = self.alphabet.index(plain_str[i])
                    if gcd((p1-p2) % 26, len(self.alphabet)) != 1:
                        continue
                c1 = self.alphabet.index(cipher_str[0])
                c2 = self.alphabet.index(cipher_str[i])
                det_inv = pow(p1-p2, -1, len(self.alphabet))
                a = (det_inv * (c1-c2)) % 26
                b = (det_inv * (c2*p1 - c1*p2)) % 26
                if gcd(a, len(self.alphabet)) != 1:
                    self.solutions[-1].add_text(self.bad_plaintext)
                    self.solutions[-1].show()
                self.solutions[-1].add_text('We first find the key by solving the system of linear equations '
                                            'a·%s+b=%s and a·%s+b=%s mod 26 where (a, b) is our key' % (p1, c1, p2, c2))
                self.solutions[-1].add_text('This gives us (%s, %s) for our key' % (a, b))
            elif self.mode == 'Ciphertext Attack':
                ciphertext = self.text_2.get_text()
                cipher_str = find_elems(ciphertext, self.alphabet)
                keys = []
                scores = []
                for a in range(len(self.alphabet)):
                    if gcd(a, len(self.alphabet)) != 1:
                        continue
                    a_inv = pow(a, -1, len(self.alphabet))
                    for b in range(len(self.alphabet)):
                        keys.append((a, b))
                        scores.append(0)
                        decrypted_lets = ''.join(self.alphabet[(a_inv*(self.alphabet.index(f)-b)) % len(self.alphabet)] for f in cipher_str)
                        for d in self.dictionary:
                            if d in decrypted_lets:
                                scores[-1] += 1
                key = keys[scores.index(max(scores))]
                a, b = key
                a_inv = pow(a, -1, len(self.alphabet))
                cipher_nums = [self.alphabet.index(f) for f in cipher_str]
                decrypted_nums = [(a_inv*(f-b)) % len(self.alphabet) for f in cipher_nums]
                decrypted_lets = [self.alphabet[f] for f in decrypted_nums]
                decrypted_text = insert_elems(ciphertext, decrypted_lets, self.alphabet)
                self.solutions[-1].add_text('We find the key via brute force. We try all possible keys and '
                                            'see which one produces text that makes sense.')
                self.solutions[-1].add_text('We find the key to be')
                self.solutions[-1].add_text('(%s, %s)' % (a, b))
                self.solutions[-1].add_text('And the decrypted text to be')
                self.solutions[-1].add_text('"' + decrypted_text + '"')
        self.solutions[-1].show()

    def help_about(self):
        self.solutions.append(SolutionWindow(self.title_text.get_text()+' '+self.mode))
        self.solutions[-1].add_text(self.help)
        self.solutions[-1].show()


def get_chunks(string, key):
    string = string.lower()
    chunks = []
    prev = False
    current = ''
    for f in string:
        if f in key:
            current += f
            prev = True
        elif prev:
            chunks.append(current)
            current = ''
            prev = False
    if current:
        chunks.append(current)
    return chunks


def find_elems(string, key):
    lets = ''
    for f in string:
        if f in key:
            lets += f
        elif f.lower() in key:
            lets += f.lower()
    return lets


def insert_elems(string, insertion, key):
    ind = 0
    new_string = ''
    for f in string:
        if f in key:
            new_string += insertion[ind]
            ind += 1
        elif f.lower() in key:
            new_string += insertion[ind].upper()
            ind += 1
        else:
            new_string += f
    return new_string


def gcd(a, b):
    while b: a, b = b, a % b
    return a


def uniform(string):
    if not string:
        return True
    a = string[0]
    for f in string:
        if f != a:
            return False
    return True


if __name__ == "__main__":
    app = QApplication(sys.argv)
    custom_font = QFont('MS Shell Dlg 2', 11)
    app.setFont(custom_font)
    win = Window()
    win.show()
    sys.exit(app.exec_())
