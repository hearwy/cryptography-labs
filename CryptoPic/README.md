# Зависимости

  * Python > 3.10
    
  * Библиотеки:
    
      * cryptography
      * Pillow
      * numpy
      * matplotlib
        
   * Установка зависимостей
     
     ```bash
        pip install -r requirements.txt
      ```

# Реализованы алгоритмы 

  * `xorshift32`
  * `AES-ECB`
  * `AES-CTR`
    
# Команды запуска    

## Общая команда 

  ```bash
     python main.py [action] [options]
  ```

### action

  * `test` - полный запуск программы, где будет зашифровка, расшифровка, создание таблица, создание гистограммы и тест NPCR/UACI
  * `encrypt` - зашифровать изображение в выбранный режим
  * `decrypt` - расшифровать зашифрованное изображение
  * Запуск через `meta.json` - передача пути к JSON-файлу первым аргументом

### option 

  * `-i` - путь к входному файлу (например, -i imgs/checkerboard.png)
  * `-o` - путь, куда сохранить результат (например, -o imgs/result.png)
  * `-a` - алгоритм шифрования(например, -a ctr)
  * `-k` - секретный ключ (например, -k mypassword)
  * `-m` - путь к файлу метаданных, куда сохраняется или откуда берется nonce (например, -m results/meta.json)
    
# Пример шифрования 

  ```bash
     python main.py encrypt -i imgs/pikachu.png -o imgs/pikachu_enc_ctr.png -a ctr -k "mypassword"
  ```

# Пример расшифрования

  ```bash
     python main.py decrypt -i imgs/pikachu_enc_ctr.png -o imgs/pikachu_dec_ctr.png -a ctr -k "mypassword" -m results/meta.json
  ```



