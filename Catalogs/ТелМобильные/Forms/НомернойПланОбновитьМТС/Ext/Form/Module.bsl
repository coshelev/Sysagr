&НаКлиенте
Процедура ПриОткрытии(Отказ)
	ОбновлениеОтображения();
КонецПроцедуры

&НаКлиенте
Процедура ОбновлениеОтображения(Элемент = Неопределено)

// Видимость кнопки для открытия файла-источника
//-------------------------------------------------------------------------------------------------
	Доступно = ЗначениеЗаполнено(ЭтаФорма.ФайлИсточник);
	Элементы.ФормаДанныеОткрыть.Видимость = Доступно;

// Доступность кнопки "ФормаДанныеЗагрузить" и выбор кнопки по-умолчанию
//-------------------------------------------------------------------------------------------------
	Доступно = (ЭтаФорма.Список.Количество() > 0);
	Элементы.ФормаДанныеЗагрузить.Видимость = Доступно;
	Элементы.ФормаДанныеЗагрузить.КнопкаПоУмолчанию = Доступно;
	Элементы.ФормаДанныеПолучить.КнопкаПоУмолчанию = (НЕ Доступно);
КонецПроцедуры

//-------------------------------------------------------------------------------------------------

&НаКлиенте
Процедура ДанныеОткрыть(Команда)

// Откроем файл-источник в ассоциированном приложении
//-------------------------------------------------------------------------------------------------
	Попытка
		ЗапуститьПриложение(СокрЛП(ЭтаФорма.ФайлИсточник));
	Исключение
	КонецПопытки;
КонецПроцедуры

&НаКлиенте
Процедура ДанныеПолучить(Команда)

// Диалог выбора файла с данными для загрузки
//-------------------------------------------------------------------------------------------------
	НовыйФайл = Новый ДиалогВыбораФайла(РежимДиалогаВыбораФайла.Открытие);
	НовыйФайл.Заголовок = "Укажите файл содержащий выписку МТС";
	НовыйФайл.Фильтр = "Таблица Excel 2003 (*.xls)|*.xls|Таблица Excel 2007 (*.xlsx)|*.xlsx";
	НовыйФайл.ПроверятьСуществованиеФайла = Истина;
	НовыйФайл.МножественныйВыбор = Ложь;

// Если файл выбран, то проверим корректность типа выбранного файла
//-------------------------------------------------------------------------------------------------
	Если (НовыйФайл.Выбрать() = Истина) Тогда
		ФайлТип = ВРег(СокрЛП(Конвертация.СловоПолучить(НовыйФайл.ПолноеИмяФайла,2,".")));

		Если (Найти(",XLS,XLSX,",ФайлТип) > 0) Тогда
			ЭтаФорма.ФайлИсточник = "";
			ДанныеПолучитьНаКлиенте(НовыйФайл.ПолноеИмяФайла);
		Иначе
			Предупреждение("Файлы выбранного типа не поддерживаются");
		КонецЕсли;
	КонецЕсли;

	ОбновлениеОтображения();
КонецПроцедуры

&НаКлиенте
Процедура ДанныеПолучитьНаКлиенте(ПолноеИмяФайла)

// Инициализация переменных
//-------------------------------------------------------------------------------------------------
	ЭтаФорма.Количество00 = 0;
	ЭтаФорма.Количество01 = 0;
	ЭтаФорма.Количество02 = 0;
	ЭтаФорма.Количество03 = 0;

// Инициализация интерфейса
//-------------------------------------------------------------------------------------------------
	Состояние("Открытие файла-источника...");
	ЭтаФорма.Список.Очистить();
	ОчиститьСообщения();

// Поместим файл во временное хранилище для передачи на сервер
//-------------------------------------------------------------------------------------------------
	ФайлТип = ВРег(СокрЛП(Конвертация.СловоПолучить(ПолноеИмяФайла,2,".")));
	ФайлАдрес = "";

	ПоместитьФайл(ФайлАдрес,ПолноеИмяФайла,,Ложь);
	ДанныеПолучитьНаСервере(ФайлАдрес,ФайлТип,ПолноеИмяФайла);
КонецПроцедуры

&НаСервере
Процедура ДанныеПолучитьНаСервере(ФайлАдрес,ФайлТип,ПолноеИмяФайла)

// Откроем файл на чтение
//-------------------------------------------------------------------------------------------------
	Попытка
		ВремФайл = ПолучитьИмяВременногоФайла(ФайлТип);
		Файл = ПолучитьИзВременногоХранилища(ФайлАдрес);
		Файл.Записать(ВремФайл);

		Источник = Новый ТабличныйДокумент;
		Источник.Прочитать(ВремФайл);
	Исключение
		ТекстСообщения = "При попытке открытия файла [" + СокрЛП(ПолноеИмяФайла);
		ТекстСообщения = ТекстСообщения + "] произошла ошибка: " + СокрЛП(ОписаниеОшибки());
		Сообщить(ТекстСообщения);
		Возврат;
	КонецПопытки;

// Если мы оказались здесь, значит файл-источник успешно открыт
//-------------------------------------------------------------------------------------------------
	ЭтаФорма.ФайлИсточник = СокрЛП(ПолноеИмяФайла);

// Создадим таблицу значений - соответствие лицевых счетов и провайдеров (для ускорения поиска)
// Создадим массив в который поместим все полученные из источника телефонные номера
//-------------------------------------------------------------------------------------------------
	ТекстЗапроса = "
	|SELECT	DISTINCT Провайдер,ЛицевойСчет
	|FROM	Справочник.ТелМобильные
	|WHERE	(ЛицевойСчет <> """")";

	Запрос = Новый Запрос;
	Запрос.Текст = ТекстЗапроса;
	ТЗКонтракты = Запрос.Выполнить().Выгрузить();
	МассивИсточник = Новый Массив;

// Проверим валидность записи
//-------------------------------------------------------------------------------------------------
	Для НомерСтроки = 2 По Источник.ВысотаТаблицы Цикл
		СимНомер = СокрЛП(Источник.Область(НомерСтроки,8,НомерСтроки,8).Текст);
		ТелНомер = СокрЛП(Источник.Область(НомерСтроки,7,НомерСтроки,7).Текст);
		ТелНомер = СокрЛП(Прав(СокрЛП(ТелНомер),10));

// Если запись валидна
// Получим номера контракта и лицевого счета для номера
// Добавим номер в массив полученных из источника номеров
//-------------------------------------------------------------------------------------------------
		Если (ЗначениеЗаполнено(ТелНомер) И ЗначениеЗаполнено(СимНомер)) Тогда
			Контракт = ВРег(СокрЛП(Источник.Область(НомерСтроки,3,НомерСтроки,3).Текст));
			ЛицевойСчет = ВРег(СокрЛП(Источник.Область(НомерСтроки,5,НомерСтроки,5).Текст));
			МассивИсточник.Добавить(ТелНомер);

// Найдем мобильный номер в справочнике
// Если номер не найден, значит пометим его к добавлению
//-------------------------------------------------------------------------------------------------
			СпрСсылка = Справочники.ТелМобильные.НайтиПоКоду(ТелНомер);

			Если (НЕ ЗначениеЗаполнено(СпрСсылка)) Тогда
				НовСтрока = ЭтаФорма.Список.Добавить();
				НовСтрока.ЛицевойСчет = ЛицевойСчет;
				НовСтрока.Контракт = Контракт;
				НовСтрока.Телефон = ТелНомер;
				НовСтрока.Карта = СимНомер;
				НовСтрока.Действие = 1;

// Попытаемся найти провайдера для добавляемого номера
//-------------------------------------------------------------------------------------------------
				НайденнаяСтрока = ТЗКонтракты.Найти(ЛицевойСчет,"ЛицевойСчет");
				ЭтаФорма.Количество01 = ЭтаФорма.Количество01 + 1;

				Если (НайденнаяСтрока <> Неопределено) Тогда
					НовСтрока.Провайдер = НайденнаяСтрока.Провайдер;
					НовСтрока.Комментарий = "Не найден в справочнике, будет добавлен";
				Иначе
					Темп = СокрЛП(Источник.Область(НомерСтроки,4,НомерСтроки,4).Текст);
					НовСтрока.Комментарий = "Не найден в справочнике (регион: " + Темп + ")";
				КонецЕсли;

				Продолжить;
			КонецЕсли;

// Номер найден в справочнике
// Проверим совпадение номеров СИМ-карт, контракта и лицевого счета
//-------------------------------------------------------------------------------------------------
			Доступно = (ВРег(СокрЛП(СимНомер)) <> ВРег(СокрЛП(СпрСсылка.НомерКарты)));
			Доступно = Доступно ИЛИ ЗначениеЗаполнено(Контракт) И (ВРег(СокрЛП(Контракт)) <> ВРег(СокрЛП(СпрСсылка.Контракт)));
			Доступно = Доступно ИЛИ ЗначениеЗаполнено(ЛицевойСчет) И (ВРег(СокрЛП(ЛицевойСчет)) <> ВРег(СокрЛП(СпрСсылка.ЛицевойСчет)));

			Если (Доступно = Истина) Тогда
				НовСтрока = ЭтаФорма.Список.Добавить();
				НовСтрока.ЛицевойСчет = ЛицевойСчет;
				НовСтрока.Контракт = Контракт;
				НовСтрока.Телефон = СпрСсылка;
				НовСтрока.Карта = СимНомер;
				НовСтрока.Действие = 2;

				НовСтрока.Комментарий = "Корректировка SIM, контракта или л/счета";
				ЭтаФорма.Количество02 = ЭтаФорма.Количество02 + 1;
				НовСтрока.Провайдер = СпрСсылка.Провайдер;
				Продолжить;
			КонецЕсли;
		КонецЕсли;
	КонецЦикла;

// На текущий момент у нас в "МассивИсточник" есть все корпоративные контрактные номера МТС
// Получим список номеров МТС из справочника "ТелМобильные" и проверим все ли номера из справочника
// есть в списке полученном от провайдера (возможно, что некоторые номера исключены из контракта)
//-------------------------------------------------------------------------------------------------
	ПустаяСсылка = Справочники.Провайдеры.ПустаяСсылка();
	СсылкаМТС = Справочники.Провайдеры.НайтиПоНаименованию("МТС",Истина,ПустаяСсылка);

	Доступно = ЗначениеЗаполнено(СсылкаМТС);
	Доступно = Доступно И (СсылкаМТС.ЭтоГруппа = Истина);

	Если (Доступно = Ложь) Тогда
		ТекстСообщения = "Не удалось найти группу ""МТС"" в справочнике ""Провайдеры"". ";
		ТекстСообщения = ТекстСообщения + "Поиск номеров исключенных из контракта не будет выполнен";
		Сообщить(ТекстСообщения);
		Возврат;
	КонецЕсли;

// Получим из справочника мобильных телефонов все записи относящиеся к иерархии МТС
//-------------------------------------------------------------------------------------------------
	ТекстЗапроса = "
	|SELECT	Ссылка
	|FROM	Справочник.ТелМобильные
	|WHERE	(Провайдер В ИЕРАРХИИ (&СсылкаМТС))";

	Запрос = Новый Запрос;
	Запрос.Текст = ТекстЗапроса;
	Запрос.УстановитьПараметр("СсылкаМТС",СсылкаМТС);
	Результат = Запрос.Выполнить().Выбрать();

// Выполним поиск каждого полученного номера в ТЗИсточник
// Если номер не найден, значит скорее всего он исключен из корпоративного контракта
//-------------------------------------------------------------------------------------------------
	Пока (Результат.Следующий()) Цикл
		Если (МассивИсточник.Найти(СокрЛП(Результат.Ссылка.Код)) = Неопределено) Тогда
			НовСтрока = ЭтаФорма.Список.Добавить();
			НовСтрока.ЛицевойСчет = Результат.Ссылка.ЛицевойСчет;
			НовСтрока.Провайдер = Результат.Ссылка.Провайдер;
			НовСтрока.Контракт = Результат.Ссылка.Контракт;
			НовСтрока.Карта = Результат.Ссылка.НомерКарты;
			НовСтрока.Телефон = Результат.Ссылка;
			НовСтрока.Действие = 3;

			ЭтаФорма.Количество03 = ЭтаФорма.Количество03 + 1;
			ВладСсылка = Телефония.ВладелецПолучить(Результат.Ссылка);

			Если (ЗначениеЗаполнено(ВладСсылка)) Тогда
				НовСтрока.Комментарий = "Исключен из контракта (" + СокрЛП(ВладСсылка) + ")";
			Иначе
				НовСтрока.Комментарий = "Исключен из контракта";
			КонецЕсли;
		КонецЕсли;
	КонецЦикла;

	ЭтаФорма.Количество00 = МассивИсточник.Количество();
	ЭтаФорма.Список.Сортировать("Действие,Телефон");
КонецПроцедуры

//-------------------------------------------------------------------------------------------------

&НаКлиенте
Процедура ДанныеЗагрузить(Команда)

// Если пользователь согласен, то выполним обработку Списка
//-------------------------------------------------------------------------------------------------
	ТекстСообщения = "Вы действительно желаете выполнить синхронизацию данных ?";
	ОчиститьСообщения();

	Если (Вопрос(ТекстСообщения,РежимДиалогаВопрос.ДаНет) = КодВозвратаДиалога.Да) Тогда
		Состояние("Обновление информационной базы из файла-источника...");
		ДанныеЗагрузитьНаСервере();

		ДанныеПолучитьНаКлиенте(ЭтаФорма.ФайлИсточник);
		Предупреждение("Готово");
		ОбновлениеОтображения();
	КонецЕсли;
КонецПроцедуры

&НаСервере
Процедура ДанныеЗагрузитьНаСервере()

// Для каждой записи Списка выполним требуемое действие
//-------------------------------------------------------------------------------------------------
	Для Каждого ТекСтрока Из ЭтаФорма.Список Цикл
		Если (ТекСтрока.Действие = 1) Тогда
			ДанныеЗагрузить01(ТекСтрока);
		ИначеЕсли (ТекСтрока.Действие = 2) Тогда
			ДанныеЗагрузить02(ТекСтрока);
		ИначеЕсли (ТекСтрока.Действие = 3) Тогда
			ДанныеЗагрузить03(ТекСтрока);
		КонецЕсли;
	КонецЦикла;
КонецПроцедуры

&НаСервере
Процедура ДанныеЗагрузить01(ТекСтрока)

// Добавим в справочник мобильных телефонов новую запись
//-------------------------------------------------------------------------------------------------
	СпрОбъект = Справочники.ТелМобильные.СоздатьЭлемент();
	СпрОбъект.Наименование = ВРег(СокрЛП(ТекСтрока.Телефон));
	СпрОбъект.НомерКарты = ВРег(СокрЛП(ТекСтрока.Карта));
	СпрОбъект.Код = СпрОбъект.Наименование;

	СпрОбъект.ЛицевойСчет = ВРег(СокрЛП(ТекСтрока.ЛицевойСчет));
	СпрОбъект.Контракт = ВРег(СокрЛП(ТекСтрока.Контракт));
	СпрОбъект.Провайдер = ТекСтрока.Провайдер;

	Попытка
		СпрОбъект.Записать();
	Исключение
		Сообщить(СокрЛП(ТекСтрока.Телефон) + ": " + СокрЛП(ОписаниеОшибки()));
	КонецПопытки;
КонецПроцедуры

&НаСервере
Процедура ДанныеЗагрузить02(ТекСтрока)

// Скорректируем реквизиты переданного телефона
//-------------------------------------------------------------------------------------------------
	Попытка
		СпрОбъект = ТекСтрока.Телефон.ПолучитьОбъект();
		СпрОбъект.НомерКарты = ВРег(СокрЛП(ТекСтрока.Карта));
		СпрОбъект.Контракт = ВРег(СокрЛП(ТекСтрока.Контракт));
		СпрОбъект.ЛицевойСчет = ВРег(СокрЛП(ТекСтрока.ЛицевойСчет));
		СпрОбъект.Записать();
	Исключение
		Сообщить(СокрЛП(ТекСтрока.Телефон) + ": " + СокрЛП(ОписаниеОшибки()));
	КонецПопытки;
КонецПроцедуры

&НаСервере
Процедура ДанныеЗагрузить03(ТекСтрока)

// Выполним удаление переданного телефона
//-------------------------------------------------------------------------------------------------
	Попытка
		СпрОбъект = ТекСтрока.Телефон.ПолучитьОбъект();
		СпрОбъект.Удалить();
	Исключение
		Сообщить(СокрЛП(ТекСтрока.Телефон) + ": " + СокрЛП(ОписаниеОшибки()));
	КонецПопытки;
КонецПроцедуры
