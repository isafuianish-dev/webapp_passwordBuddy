# Password Buddy

A local-first password manager that lives entirely in your browser. Password Buddy keeps your passwords, one-time codes, and notes organized into "books" (like Personal and Office), and encrypts everything with a master key that only you know.

## Master key and encryption

The first time you open Password Buddy, you'll be asked to create a **master key**. This key never leaves your browser and is never saved anywhere — it's used to derive an encryption key (PBKDF2 + AES-GCM) that protects your saved passwords, one-time password secrets, and password history. Book names, entry titles, usernames, URLs, and notes are kept as plain text so your vault stays easy to browse and search; only the sensitive values are encrypted.

Because Password Buddy never stores your master key, **if you forget it, your saved passwords cannot be recovered.** Write it down somewhere safe. If you're truly locked out, the "Forgot your master key?" link on the unlock screen lets you wipe the app's local data and start fresh.

Every time you reload the page, you'll need to unlock with your master key again — there's a **Lock** button in the top bar if you want to lock the vault without closing the tab.

## Books

The sidebar on the left holds your **books** — categories like "Personal" or "Office" for organizing your passwords. Two books are created for you automatically. Use **+ Add Book** to create more, and hover over a book to reveal rename and delete icons. Deleting a book also deletes every password saved inside it, after a confirmation.

## Saved passwords

Click a book to see its passwords laid out as a grid of cards. Each card shows:
- The entry's **title**
- Its **username or email** (with a one-click copy button)
- Its **password**, masked as dots (with a one-click copy button that decrypts just long enough to copy it)
- If a one-time password secret is set up, a live **6-digit TOTP code** next to a small circular countdown ring that fills up over each 30-second window and refreshes automatically

The search box above the grid filters the current book's passwords by title or username.

Click anywhere on a card (other than its icon buttons) to open it in a details view showing the book, username, password (reveal/hide and copy), one-time code, every saved URL, notes, and the full password history. From there, **Edit** switches to an editable form, and **Delete** removes the entry after confirmation.

**+ New Password** opens the same form, empty and pre-set to the book you're viewing, to create a new entry.

### Editing an entry

- **Password**: shown as plain text while editing, with a show/hide toggle.
- **TOTP secret**: optional — paste the base32 secret a service gives you when you set up two-factor authentication, and Password Buddy will generate live 6-digit codes for it.
- **URLs**: add as many labeled links as you want (e.g. "Login" / "Recovery"), and remove any you don't need.
- **Notes**: a free-text field for anything else worth remembering about this entry.

### Password history

Whenever you save an entry with a changed password, the previous password is kept in its **history** (most recent first, up to the last 20). Each history entry can be individually revealed or copied, alongside a relative timestamp of when it was replaced.

## Changing your master key

Open **Settings** (gear icon, top right) and scroll to **Change Master Key**. Enter your current master key plus a new one (twice, to confirm). Password Buddy re-encrypts every saved password, OTP secret, and history entry under the new key before saving — your data itself never changes, only what protects it.

## Export and import

- **Export** (download icon, sidebar) downloads all your books and passwords as a single JSON file. Book names, titles, usernames, URLs, and notes are readable in the file; passwords, OTP secrets, and password history values are individually encrypted and unreadable without your master key.
- **Import** (upload icon, sidebar) loads a previously exported file back in. You'll be asked for the master key that file was encrypted with (handy if you're restoring a backup on a new browser with a different master key) before anything is decrypted. If you already have books and passwords saved, you'll be asked whether to **Append** the imported data or **Clean up & Replace** everything.

## How your data is saved

Everything — your master key's salt/verifier and your encrypted vault — is saved **directly in your browser's local storage**. There is no account, sign-in, or server involved, and nothing you store here ever leaves your computer unless you use Export. Because it's local to one browser, use Export and Import to move your vault to another browser or device.

## Customization

Click the gear icon in the top-right corner to open **Settings**, where you can:
- Switch between **Light** and **Dark** theme
- Choose an **accent color** from six options: Indigo, Blue, Green, Rose, Amber, or Purple
- Change your master key (see above)

Your theme and accent choices are remembered automatically for the next time you open the app.
