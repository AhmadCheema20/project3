import struct
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.spinner import Spinner

# RC5 Algorithm Implementation
class RC5:
    def __init__(self, key: bytes, word_size: int = 32, rounds: int = 12):
        self.word_size = word_size
        self.rounds = rounds
        self.w = word_size
        self.r = rounds
        self.b = len(key)
        self.t = 2 * (self.r + 1)
        self.key = key
        self.mod = 2 ** self.w
        self.P = 0xb7e15163
        self.Q = 0x9e3779b9

        self.S = self.key_expansion()

    def key_expansion(self):
        L = [0] * (self.b // 4)
        for i in range(self.b - 1, -1, -1):
            L[i // 4] = (L[i // 4] << 8) + self.key[i]

        S = [self.P]
        for i in range(1, self.t):
            S.append((S[i - 1] + self.Q) % self.mod)

        i = j = A = B = 0
        for k in range(3 * max(self.t, len(L))):
            A = S[i] = self.lshift((S[i] + A + B) % self.mod, 3)
            B = L[j] = self.lshift((L[j] + A + B) % self.mod, (A + B) % self.w)
            i = (i + 1) % self.t
            j = (j + 1) % len(L)

        return S

    def encrypt(self, plaintext):
        A, B = struct.unpack('<2L', plaintext)
        A = (A + self.S[0]) % self.mod
        B = (B + self.S[1]) % self.mod
        for i in range(1, self.r + 1):
            A = (self.lshift(A ^ B, B) + self.S[2 * i]) % self.mod
            B = (self.lshift(B ^ A, A) + self.S[2 * i + 1]) % self.mod
        return struct.pack('<2L', A, B)

    def decrypt(self, ciphertext):
        A, B = struct.unpack('<2L', ciphertext)
        for i in range(self.r, 0, -1):
            B = self.rshift((B - self.S[2 * i + 1]) % self.mod, A) ^ A
            A = self.rshift((A - self.S[2 * i]) % self.mod, B) ^ B
        B = (B - self.S[1]) % self.mod
        A = (A - self.S[0]) % self.mod
        return struct.pack('<2L', A, B)

    def lshift(self, val, n):
        n = n % self.w
        return ((val << n) & (self.mod - 1)) | (val >> (self.w - n))

    def rshift(self, val, n):
        n = n % self.w
        return (val >> n) | ((val << (self.w - n)) & (self.mod - 1))

# Kivy Application
class RC5App(App):
    def build(self):
        self.title = 'RC5 Encryption/Decryption'

        layout = BoxLayout(orientation='vertical', padding=10, spacing=10)

        self.mode_spinner = Spinner(
            text='Encrypt',
            values=('Encrypt', 'Decrypt'),
            size_hint=(1, 0.2)
        )
        layout.add_widget(self.mode_spinner)

        self.input_label = Label(text='Input (Hex):', size_hint=(1, 0.1))
        layout.add_widget(self.input_label)

        self.input_text = TextInput(size_hint=(1, 0.2), multiline=False)
        layout.add_widget(self.input_text)

        self.key_label = Label(text='Key (Hex):', size_hint=(1, 0.1))
        layout.add_widget(self.key_label)

        self.key_text = TextInput(size_hint=(1, 0.2), multiline=False)
        layout.add_widget(self.key_text)

        self.result_label = Label(text='Result:', size_hint=(1, 0.1))
        layout.add_widget(self.result_label)

        self.result_text = TextInput(size_hint=(1, 0.2), multiline=False, readonly=True)
        layout.add_widget(self.result_text)

        self.process_button = Button(text='Process', size_hint=(1, 0.2))
        self.process_button.bind(on_press=self.process)
        layout.add_widget(self.process_button)

        return layout

    def process(self, instance):
        mode = self.mode_spinner.text
        input_hex = self.input_text.text
        key_hex = self.key_text.text

        try:
            input_bytes = bytes.fromhex(input_hex)
            key_bytes = bytes.fromhex(key_hex)

            rc5 = RC5(key_bytes)

            if mode == 'Encrypt':
                result_bytes = rc5.encrypt(input_bytes)
            else:
                result_bytes = rc5.decrypt(input_bytes)

            result_hex = result_bytes.hex()
            self.result_text.text = result_hex
        except Exception as e:
            self.result_text.text = f"Error: {e}"

if __name__ == '__main__':
    RC5App().run()
