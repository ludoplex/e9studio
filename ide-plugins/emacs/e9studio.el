;;; e9studio.el --- E9Studio Binary Editor Integration -*- lexical-binding: t -*-

;; Copyright (C) 2024 E9Patch Contributors
;; License: GPL-3.0-or-later

;; Author: E9Patch Contributors
;; Version: 1.0.0
;; Package-Requires: ((emacs "27.1") (json "1.5"))
;; Keywords: tools, binary, reverse-engineering
;; URL: https://github.com/e9patch/e9studio

;;; Commentary:

;; E9Studio integration for Emacs.  Provides binary analysis,
;; disassembly, decompilation, and patching capabilities.
;;
;; Usage:
;;   M-x e9studio-open-binary    - Open a binary file
;;   M-x e9studio-disassemble    - Disassemble at address
;;   M-x e9studio-decompile      - Decompile function
;;   M-x e9studio-functions      - List functions
;;   M-x e9studio-patch-nop      - NOP bytes at address
;;   M-x e9studio-apply-patches  - Apply all patches
;;   M-x e9studio-save-binary    - Save patched binary

;;; Code:

(require 'json)
(require 'cl-lib)

;;; Customization

(defgroup e9studio nil
  "E9Studio binary editor integration."
  :group 'tools
  :prefix "e9studio-")

(defcustom e9studio-executable "e9studio.com"
  "Path to the e9studio.com executable."
  :type 'string
  :group 'e9studio)

(defcustom e9studio-show-bytes nil
  "If non-nil, show raw bytes in disassembly."
  :type 'boolean
  :group 'e9studio)

;;; Internal Variables

(defvar e9studio--process nil
  "The E9Studio subprocess.")

(defvar e9studio--request-id 0
  "Counter for JSON-RPC request IDs.")

(defvar e9studio--callbacks (make-hash-table :test 'equal)
  "Hash table mapping request IDs to callbacks.")

(defvar e9studio--current-binary nil
  "Path to the currently open binary.")

(defvar e9studio--response-buffer ""
  "Buffer for accumulating response data.")

;;; Process Management

(defun e9studio--next-id ()
  "Get the next request ID."
  (cl-incf e9studio--request-id))

(defun e9studio--start ()
  "Start the E9Studio process."
  (unless (and e9studio--process (process-live-p e9studio--process))
    (setq e9studio--process
          (make-process
           :name "e9studio"
           :buffer nil
           :command (list e9studio-executable "--ide-mode")
           :connection-type 'pipe
           :filter #'e9studio--filter
           :sentinel #'e9studio--sentinel))
    ;; Initialize
    (e9studio--send-request
     "initialize"
     '((clientInfo . ((name . "emacs-e9studio") (version . "1.0.0"))))
     (lambda (result error)
       (if error
           (message "E9Studio: Initialization failed: %s" error)
         (message "E9Studio: Connected"))))))

(defun e9studio--stop ()
  "Stop the E9Studio process."
  (when (and e9studio--process (process-live-p e9studio--process))
    (delete-process e9studio--process))
  (setq e9studio--process nil)
  (setq e9studio--current-binary nil))

(defun e9studio--sentinel (process event)
  "Handle PROCESS events."
  (when (string-match-p "\\(finished\\|exited\\|killed\\)" event)
    (setq e9studio--process nil)
    (setq e9studio--current-binary nil)
    (message "E9Studio: Process terminated")))

(defun e9studio--filter (process output)
  "Filter function for PROCESS OUTPUT."
  (setq e9studio--response-buffer
        (concat e9studio--response-buffer output))
  ;; Try to parse complete messages
  (while (string-match "Content-Length: \\([0-9]+\\)\r?\n\r?\n" e9studio--response-buffer)
    (let* ((content-length (string-to-number (match-string 1 e9studio--response-buffer)))
           (header-end (match-end 0))
           (total-length (+ header-end content-length)))
      (when (>= (length e9studio--response-buffer) total-length)
        (let* ((json-str (substring e9studio--response-buffer header-end total-length))
               (response (json-read-from-string json-str)))
          (setq e9studio--response-buffer
                (substring e9studio--response-buffer total-length))
          (e9studio--handle-response response))))))

(defun e9studio--handle-response (response)
  "Handle a JSON-RPC RESPONSE."
  (let ((id (alist-get 'id response))
        (result (alist-get 'result response))
        (error (alist-get 'error response)))
    (when id
      (let ((callback (gethash id e9studio--callbacks)))
        (when callback
          (remhash id e9studio--callbacks)
          (funcall callback result error))))))

;;; JSON-RPC

(defun e9studio--send-request (method params callback)
  "Send a JSON-RPC request with METHOD and PARAMS.
CALLBACK is called with (result error) when response arrives."
  (e9studio--start)
  (let* ((id (e9studio--next-id))
         (request (json-encode
                   `((jsonrpc . "2.0")
                     (id . ,id)
                     (method . ,method)
                     (params . ,params))))
         (header (format "Content-Length: %d\r\n\r\n" (length request))))
    (puthash id callback e9studio--callbacks)
    (process-send-string e9studio--process (concat header request))))

;;; Interactive Commands

;;;###autoload
(defun e9studio-open-binary (path)
  "Open binary file at PATH for analysis."
  (interactive "fBinary file: ")
  (e9studio--send-request
   "binary/open"
   `((path . ,(expand-file-name path)))
   (lambda (result error)
     (if error
         (message "E9Studio: Failed to open binary: %s"
                  (alist-get 'message error))
       (setq e9studio--current-binary path)
       (message "E9Studio: Opened %s %s binary (%d functions)"
                (alist-get 'arch result)
                (alist-get 'format result)
                (alist-get 'numFunctions result))))))

;;;###autoload
(defun e9studio-close-binary ()
  "Close the currently open binary."
  (interactive)
  (e9studio--send-request
   "binary/close"
   '()
   (lambda (_result error)
     (if error
         (message "E9Studio: Failed to close binary: %s"
                  (alist-get 'message error))
       (setq e9studio--current-binary nil)
       (message "E9Studio: Binary closed")))))

;;;###autoload
(defun e9studio-disassemble (address)
  "Disassemble code starting at ADDRESS."
  (interactive "sAddress (hex): ")
  (unless e9studio--current-binary
    (user-error "No binary is open"))
  (let ((addr (if (string-prefix-p "0x" address)
                  (string-to-number (substring address 2) 16)
                (string-to-number address 16))))
    (e9studio--send-request
     "analysis/getDisassembly"
     `((address . ,addr) (count . 50))
     (lambda (result error)
       (if error
           (message "E9Studio: Disassembly failed: %s"
                    (alist-get 'message error))
         (e9studio--show-disassembly result))))))

(defun e9studio--show-disassembly (result)
  "Show disassembly RESULT in a buffer."
  (let ((buf (get-buffer-create "*E9Studio Disassembly*")))
    (with-current-buffer buf
      (let ((inhibit-read-only t))
        (erase-buffer)
        (dolist (insn (alist-get 'instructions result))
          (insert (format "%s  %s\n"
                          (alist-get 'address insn)
                          (alist-get 'text insn))))
        (goto-char (point-min))
        (asm-mode)
        (read-only-mode 1)))
    (switch-to-buffer-other-window buf)))

;;;###autoload
(defun e9studio-decompile (address)
  "Decompile function at ADDRESS."
  (interactive "sFunction address (hex): ")
  (unless e9studio--current-binary
    (user-error "No binary is open"))
  (let ((addr (if (string-prefix-p "0x" address)
                  (string-to-number (substring address 2) 16)
                (string-to-number address 16))))
    (e9studio--send-request
     "analysis/getDecompilation"
     `((address . ,addr))
     (lambda (result error)
       (if error
           (message "E9Studio: Decompilation failed: %s"
                    (alist-get 'message error))
         (e9studio--show-decompilation result))))))

(defun e9studio--show-decompilation (result)
  "Show decompilation RESULT in a buffer."
  (let ((buf (get-buffer-create "*E9Studio Decompilation*")))
    (with-current-buffer buf
      (let ((inhibit-read-only t))
        (erase-buffer)
        (insert (alist-get 'code result))
        (goto-char (point-min))
        (c-mode)
        (read-only-mode 1)))
    (switch-to-buffer-other-window buf)))

;;;###autoload
(defun e9studio-functions ()
  "List all functions in the binary."
  (interactive)
  (unless e9studio--current-binary
    (user-error "No binary is open"))
  (e9studio--send-request
   "analysis/getFunctions"
   '()
   (lambda (result error)
     (if error
         (message "E9Studio: Failed to get functions: %s"
                  (alist-get 'message error))
       (e9studio--show-functions result)))))

(defun e9studio--show-functions (result)
  "Show function list RESULT."
  (let ((buf (get-buffer-create "*E9Studio Functions*")))
    (with-current-buffer buf
      (let ((inhibit-read-only t))
        (erase-buffer)
        (insert "Address          Size    Name\n")
        (insert (make-string 60 ?-) "\n")
        (dolist (func (alist-get 'functions result))
          (let ((name (alist-get 'name func))
                (addr (alist-get 'address func))
                (size (alist-get 'size func)))
            (insert (format "%-16s %6d  %s\n"
                            addr size
                            (if (string-empty-p name)
                                (concat "sub_" (substring addr 2))
                              name)))))
        (goto-char (point-min))
        (read-only-mode 1)))
    (switch-to-buffer-other-window buf)))

;;;###autoload
(defun e9studio-patch-nop (address size)
  "NOP SIZE bytes at ADDRESS."
  (interactive "sAddress (hex): \nnSize (bytes): ")
  (unless e9studio--current-binary
    (user-error "No binary is open"))
  (let ((addr (if (string-prefix-p "0x" address)
                  (string-to-number (substring address 2) 16)
                (string-to-number address 16))))
    (e9studio--send-request
     "patch/nop"
     `((address . ,addr) (size . ,size))
     (lambda (result error)
       (if error
           (message "E9Studio: Patch failed: %s"
                    (alist-get 'message error))
         (message "E9Studio: Created NOP patch (id: %d)"
                  (alist-get 'patchId result)))))))

;;;###autoload
(defun e9studio-apply-patches ()
  "Apply all pending patches."
  (interactive)
  (e9studio--send-request
   "patch/apply"
   '()
   (lambda (_result error)
     (if error
         (message "E9Studio: Apply failed: %s"
                  (alist-get 'message error))
       (message "E9Studio: Patches applied")))))

;;;###autoload
(defun e9studio-save-binary (path)
  "Save patched binary to PATH."
  (interactive "FSave patched binary to: ")
  (e9studio--send-request
   "patch/save"
   `((path . ,(expand-file-name path)))
   (lambda (_result error)
     (if error
         (message "E9Studio: Save failed: %s"
                  (alist-get 'message error))
       (message "E9Studio: Saved to %s" path)))))

;;; Mode

(defvar e9studio-mode-map
  (let ((map (make-sparse-keymap)))
    (define-key map (kbd "C-c C-o") #'e9studio-open-binary)
    (define-key map (kbd "C-c C-d") #'e9studio-disassemble)
    (define-key map (kbd "C-c C-c") #'e9studio-decompile)
    (define-key map (kbd "C-c C-f") #'e9studio-functions)
    (define-key map (kbd "C-c C-n") #'e9studio-patch-nop)
    (define-key map (kbd "C-c C-a") #'e9studio-apply-patches)
    (define-key map (kbd "C-c C-s") #'e9studio-save-binary)
    map)
  "Keymap for E9Studio mode.")

;;;###autoload
(define-minor-mode e9studio-mode
  "Minor mode for E9Studio binary editing."
  :lighter " E9"
  :keymap e9studio-mode-map
  :group 'e9studio)

(provide 'e9studio)
;;; e9studio.el ends here
