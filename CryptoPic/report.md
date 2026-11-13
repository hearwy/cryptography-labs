# Отчет

## Постановка задачи

Реализованные методы шифрования:

  * Потоковый шифр на базе генератора псевдослучайных чисел `xorshift32`
  * Блочный шифр `AES-ECB`
  * Блочный шифр `AES-CTR`
    
Используемые изображения: градиент(`gradient.png`), шахматная доска(`checkerboard.png`), тестовое изображение пикачу(`pikachu.png`).

Предмет сравнения:

  * Сохранение визуальной структуры и паттернов открытого текста в шифротексте
  * Информационная энтропия распределения байтов. Коэффициенты корреляции соседних пикселей по горизонтали и вертикали
  * Чувствительность алгоритма к изменению одного бита ключа
  * Строгая побайтовая обратимость преобразований

## Реализация

Первые 4 байта `SHA-256` хэша ключа задают 32-битное начальное состояние (`seed`), из которого генератор `XORShift32` формирует псевдослучайную гамму. В функции `xor_cipher` каждый байт изображения складывается по модулю 2 с байтом гаммы. Расшифрование выполняется этой же функцией благодаря симметричности операции XOR.

  ```python

    def next_u32(self) -> int:
      x = self.state
      x = (x ^ (x << 13)) & 0xFFFFFFFF
      x = (x ^ (x >> 17)) & 0xFFFFFFFF
      x = (x ^ (x << 5)) & 0xFFFFFFFF
      self.state = x
      return x

    def xor_cipher(data: bytes, key: str | bytes) -> bytes:
      seed = derive_seed(key)
      prng = XORShift32(seed)
      keystream = prng.byte_stream()
      return bytes(b ^ next(keystream) for b in data)

   ```

Подготовливаем ключ и паддинг, а именно пароль через `SHA-256` приводится к 32 байтам ключа `AES-256`. Функции `pkcs7` дописывают недостающие байты до размера блока в 16 байт при зашифровании и удаляют их при расшифровании.

```python

    def derive_key(key: str | bytes) -> bytes:
        if isinstance(key, bytes) and len(key) == 32:
            return key
        if isinstance(key, str):
            key = key.encode("utf-8")
        return hashlib.sha256(key).digest()

    def pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
        padding_len = block_size - (len(data) % block_size)
        return data + bytes([padding_len] * padding_len)

   ```

В режиме `AES-ECB` массив пикселей разбивается на независимые 16-байтные блоки: некратные блоки дополняются паддингом `pkcs7`, после чего шифруются с 256-битным ключом `SHA-256`. При расшифровании блоки восстанавливаются в исходный порядок, а добавленный паддинг удаляется. Поскольку размер картинки не всегда делится на 16 нацело, `pkcs7` дополняет последний блок байтами и шифротекст становится длиннее исходного растра. Чтобы при сохранении в стандартный png ничего не терялось, этот избыточный хвост (`ecb_tail`) записывается в `results/meta.json`, при расшифровании этот хвост берется обратно, склеивает с пикселями и собирает файл.

```python

    def encrypt_ecb(data: bytes, key: str | bytes) -> bytes:
       aes_key = derive_key(key)
       padded = False
       if len(data) % 16 != 0:
           data = pad_pkcs7(data, block_size=16)
           padded = True
       cipher = Cipher(algorithms.AES(aes_key), modes.ECB())
       encryptor = cipher.encryptor()
       return encryptor.update(data) + encryptor.finalize()

    def decrypt_ecb(data: bytes, key: str | bytes, is_padded: bool = False) -> bytes:
        aes_key = derive_key(key)
        cipher = Cipher(algorithms.AES(aes_key), modes.ECB())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(data) + decryptor.finalize()
        if is_padded:
            return unpad_pkcs7(decrypted)
        return decrypted

   ```

`AES-CTR` превращает блочный шифр в потоковый. Шифруется случайная метка (nonce) со счётчиком, порождая гамму, которая складывается с пикселями через XOR без необходимости дополнения данных.

```python

    def encrypt_ctr(data: bytes, key: str | bytes, nonce: bytes | None = None) -> tuple[bytes, bytes]:
       aes_key = derive_key(key)
       if nonce is None:
           nonce = os.urandom(16)
       cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce))
       encryptor = cipher.encryptor()
       ciphertext = encryptor.update(data) + encryptor.finalize()
       return ciphertext, nonce

    def decrypt_ctr(data: bytes, key: str | bytes, nonce: bytes) -> bytes:
        aes_key = derive_key(key)
        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce))
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()

   ```

Хранение IV / Nonce: 
  * Для режима `AES-CTR` случайный 16-байтный вектор инициализации генерируется криптостойким `os.urandom(16)`.
  * Вектор инициализации преобразуется в hex-строку и сохраняется в файле `meta.json` вместе с названием алгоритма и именем файла. При расшифровании функция `load_metadata` считывает `JSON` и конвертирует `hex` обратно в 16 байтов `nonce_bytes`.

```python

     def save_metadata(
         filepath: str,
         algorithm: str,
         source_filename: str,
         nonce: bytes | None = None,
         tail: bytes | None = None,
     ) -> None:
         path = Path(filepath)
         meta = {}
         if path.exists():
             try:
                 with open(path, "r", encoding="utf-8") as f:
                     meta = json.load(f)
             except json.JSONDecodeError:
                 meta = {}
     
         meta["algorithm"] = algorithm
         meta["source"] = source_filename

         #Если передан вектор инициализации (для CTR), переводим его в hex-строку для JSON
         if nonce is not None:
             meta["nonce"] = nonce.hex()

         #Если передан хвост паддинга (для ECB), сохраняем его
         if tail is not None:
             meta["ecb_tail"] = tail.hex()
         else:
             meta.pop("ecb_tail", None)

         #Сохранение в JSON
         path.parent.mkdir(parents=True, exist_ok=True)
         with open(path, "w", encoding="utf-8") as f:
             json.dump(meta, f, indent=2, ensure_ascii=False)
     
     def load_metadata(filepath: str) -> dict:
         with open(filepath, "r", encoding="utf-8") as f:
             data = json.load(f)
         #Если в метаданных есть nonce в виде hex-строки, конвертируем его обратно в байты
         if "nonce" in data and data["nonce"]:
             data["nonce_bytes"] = bytes.fromhex(data["nonce"])
         #Если есть сохраненный хвост паддинга, тоже переводим его из hex-строки в байты
         if "ecb_tail" in data and data["ecb_tail"]:
             data["tail_bytes"] = bytes.fromhex(data["ecb_tail"])
         return data

   ```

Проверка обратимости (SHA-256): 

  * Для каждого метода исходный байтовый поток пикселей шифруется, затем расшифровывается.
  * До начала шифрования для массива пикселей рассчитывается контрольная сумма SHA-256.
    
    ```python
      def compute_sha256(data: bytes) -> str:
          return hashlib.sha256(data).hexdigest()
       ```
    
  * После шифрования байты упаковываются в растровое изображение заданного формата и сохраняются на диск как файл png.
  * Скрипт заново открывает сохранённый png с диска через Image.open(...), вытягивает из него байтовый поток методом `.tobytes()` и передает его в функцию расшифрования вместе с метаданными.
  * Хэш-сумма `SHA-256` и содержимое расшифрованного потока побайтово сравниваются с оригиналом.

    ```python
    
      enc_ctr_bytes, used_nonce = encrypt_ctr(raw_pixels, secret_key, nonce=nonce)

      #Сохранение зашифрованного файла на диск и запись метаданных
      Image.frombytes(mode, size, enc_ctr_bytes).save(enc_ctr_path)
      save_metadata(meta_path, "aes-ctr", src_path.name, nonce=used_nonce)
      
      #Чтение зашифрованного png обратно с диска
      loaded_ctr_bytes = Image.open(enc_ctr_path).tobytes()
      ctr_meta = load_metadata(meta_path)

      #Расшифровка байтов, полученных с диска
      dec_ctr_bytes = decrypt_ctr(loaded_ctr_bytes, secret_key, nonce=ctr_meta["nonce_bytes"])
      
      record = {
          "method": "AES-CTR",
          "original_sha256": original_hash,
          "restored_sha256": compute_sha256(dec_ctr_bytes),
          "exact_match": (raw_pixels == dec_ctr_bytes),
      }
    
       ```

## Методика эксперимента

Для изображения `pikachu` проводилось основное статистическое сравнение.

Оценивались:

  * Cтепень хаотичности и равномерности распределения значений байтов
  * Коэффициент корреляции, то есть оценивалась линейная зависимость между смежными пикселями по горизонтали и вертикали.
  * Метрики `NPCR` и `UACI`
  * Гистограммы распределения интенсивности

Для расчёта корреляции по горизонтали и вертикали использовалась случайная выборка до 50 000 пар соседних пикселей. Это ускоряет вычисления без потери статистической точности.

  ```python
    
      #Извлечение первого цветового канала для цветного изображения
      if len(shape) == 3:
          corr_h, corr_v = compute_correlations(arr_2d[:, :, 0])
      
      #Формирование соседних пар и выборка до 50 000 элементов
      h_pairs_x = img_array[:, :-1].flatten()
      h_pairs_y = img_array[:, 1:].flatten()
      
      if len(h_pairs_x) > max_samples:
          indices = np.random.choice(len(h_pairs_x), max_samples, replace=False)
          corr_h = compute_correlation_pair(h_pairs_x[indices], h_pairs_y[indices])
    
   ```

Для оценки лавинного эффекта (NPCR и UACI) из базового секретного ключа ("ggwp") через SHA-256 формируется 256-битный ключ k1, после чего в его первом байте инвертируется ровно 1 младший бит (k2 = bytes([k1[0] ^ 1]) + k1[1:]). Картинка шифруется алгоритмом AES-CTR дважды с этими ключами при фиксированном нулевом векторе nonce:

  ```python

     def run_key_sensitivity_test(
         image_bytes: bytes,
         base_key: str = "ggwp",
     ) -> dict:
         k1 = derive_key(base_key)

         #Создание измененненного ключа k2 из k1 путем изменения первого бита
         k2 = bytes([k1[0] ^ 1]) + k1[1:]

         #Фиксация одинакового вектора инициализации (nonce) для корректности сравнения
         nonce = b"\x00"*16

         c1, _ = encrypt_ctr(image_bytes, k1, nonce=nonce)
         c2, _ = encrypt_ctr(image_bytes, k2, nonce=nonce)
         npcr, uaci = compute_npcr_uaci(c1, c2)
         return {
             "method": "AES-CTR (изменение 1 бита ключа)",
             "NPCR": npcr,
             "UACI": uaci,
         }
    
  ```

## Результаты

Сводная таблица метрик

| № | Метод | Энтропия | Corr H | Corr V | Особенности | 
| :-: | :--- | :-: | :-: | :-: | :-: | 
| 1 | Исходное изображение | 4.313 | 0.8697 | 0.8248 | Само изображение | 
| 2 | Потоковый XOR | 7.999 | -0.0062 | 0.0033 | Цветовой шум | 
| 3 | AES-ECB | 7.362 | -0.0243 | 0.5109 | Цветовой шум, но видно очертания изображения | 
| 4 | AES-CTR | 7.9991 | 0.0067 | 0.0039 | Цветовой шум | 

Гистограмма исходного изображения, потокового `XOR`, `AES-ECB` и `AES-CTR`

![gist](./results/histograms.png)

Результаты проверки обратимости

  * Исходное изображение
    
    ![pika](./imgs/pikachu.png)

  * `XOR`
    
    ![pika_xor](./imgs/pikachu_enc_xor.png)
    
  * `AES-ECB`
    
    ![pika_ecb](./imgs/pikachu_enc_ecb.png)
    
  * `AES-CTR`
    
    ![pika_ctr](./imgs/pikachu_enc_ctr.png)

`NPCR`/`UACI` для эксперимента с ключом с помощью `AES-CTR`

  * Изменяем второй ключ на один бит и получаем `NPCR` = 99.5728%, `UACI` = 33.5050%

## Анализ 

Исходное изображение отличается сильной линейной зависимостью между соседними пикселями и низкой энтропией, что типично для картинок с крупными областями одного цвета. Методы `AES-CTR` и потоковый `XOR` энтропия практически достигает теоретический максимум, а корреляция снизилась почти до нуля. Визуально и статистически структура изображения полностью разрушается, превращаясь в цветной шум. Метод `AES-ECB`, наоборот, показал другие результаты: по горизонтали корреляция хоть и снизилась, но по вертикали сохранилась высокая зависимость, а энтропия составила всего 7.3, что далековато от 8. Разница между методами заключается в том что в `AES-ECB` каждый 16-байтный блок шифруется изолированно, из-за чего одинаковые участки фона превращаются в идентичные блоки шифра и сохраняют очертания рисунка. В методе `AES-CTR` такой проблемы нет, так как за счет счетчика и вектора `nonce` для каждого блока вырабатывается своя уникальная гамма, гарантирующая случайный результат. Все это можно увидеть на гистограмме:  у `AES-CTR` и `XOR` распределение выровнялось в сплошную полку по всем 256 значениям, а на гистограмме `AES-ECB` хорошо видно повторяющиеся всплески.

## Вывод

Эксперимент показал, что статистический анализ наглядно показывает слабые места шифрования. Режим `AES-ECB` не подходит для изображений с высокой избыточностью, так как сохраняет визуальные контуры и вертикальную корреляцию. Потоковое гаммирование на базе `XORShift32` хорошо маскирует статистику картинки, но не даёт реальной криптографической защиты, так как его без проблем можно расшифровать. Полноценную стойкость, скрытие структуры и выраженный лавинный эффект при изменении одного бита ключа обеспечивает только `AES-CTR`.
