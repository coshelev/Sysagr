﻿&НаСервере
Процедура ПриСозданииНаСервере(Отказ,СтандартнаяОбработка)
	
	// Получим ссылки на контакт-центры в которых зарегистрирован текущий пользователь
	//-------------------------------------------------------------------------------------------------
	ТекстЗапроса = 
	"ВЫБРАТЬ РАЗЛИЧНЫЕ
	|	КонтактЦентрыПользователи.Ссылка КАК Ссылка,
	|	КонтактЦентрыПользователи.Ссылка.Очередь КАК Очередь,
	|	КонтактЦентрыПользователи.Ссылка.Очередь.Сервер.ИсточникДанных КАК Сервер,
	|	КонтактЦентрыПользователи.Ссылка.ИспользуетсяКаскадОчередей КАК ИспользуетсяКаскадОчередей
	|ИЗ
	|	Справочник.КонтактЦентры.Пользователи КАК КонтактЦентрыПользователи
	|ГДЕ
	|	КонтактЦентрыПользователи.Пользователь = &Пользователь
	|
	|УПОРЯДОЧИТЬ ПО
	|	КонтактЦентрыПользователи.Ссылка.Наименование,
	|	КонтактЦентрыПользователи.Ссылка.Очередь.Наименование";
	
	Запрос = Новый Запрос;
	Запрос.Текст = ТекстЗапроса;
	Запрос.УстановитьПараметр("Пользователь",ПараметрыСеанса.ТекущийПользователь);
	ТЗТемп = Запрос.Выполнить().Выгрузить();
	
	// Для каждого контакт-центра получим основную системную очередь
	// Для полученной очереди сформируем список телефонов, которые зарегистрированы как агенты очереди
	//-------------------------------------------------------------------------------------------------
	Для Каждого ТекЦентр Из ТЗТемп Цикл
		
		Если ТекЦентр.ИспользуетсяКаскадОчередей = Ложь Тогда
			
			ТекстЗапроса = "
			|SELECT	DISTINCT MemberName AS Телефон
			|FROM	ВнешнийИсточникДанных." + СокрЛП(ТекЦентр.Сервер) + ".Таблица.Агенты
			|WHERE	(queue_name = &Очередь)
			|ORDER	BY Телефон";
			
			Запрос = Новый Запрос;
			Запрос.Текст = ТекстЗапроса;
			Запрос.УстановитьПараметр("Очередь",ВРег(СокрЛП(ТекЦентр.Очередь.Наименование)));
			Попытка
				Результат = Запрос.Выполнить().Выбрать();
			Исключение
				Комментарий = ОписаниеОшибки();
				ЗаписьЖурналаРегистрации("ПриСозданииНаСервере", УровеньЖурналаРегистрации.Ошибка, Метаданные.Обработки.КонсольКонтактЦентра.Формы.ФормаВыбораОператора,,Комментарий);
				Продолжить
			КонецПопытки;
			
			Пока (Результат.Следующий()) Цикл
				ТелСсылка = Конвертация.ТелВнутреннийПолучитьСсылку(Результат.Телефон);
				
				Если (ЗначениеЗаполнено(ТелСсылка)) Тогда
					НовСтрока = ЭтаФорма.Список.Добавить();
					НовСтрока.КонтактЦентр = ТекЦентр.Ссылка;
					НовСтрока.Очередь = ТекЦентр.Очередь;
					НовСтрока.Телефон = ТелСсылка;
				КонецЕсли;
			КонецЦикла;
		Иначе
			
			Запрос = Новый Запрос();
			Запрос.Текст =
			"ВЫБРАТЬ
			|	КонтактЦентрыКаскадОчередей.Очередь КАК Очередь
			|ИЗ
			|	Справочник.КонтактЦентры.КаскадОчередей КАК КонтактЦентрыКаскадОчередей
			|ГДЕ
			|	КонтактЦентрыКаскадОчередей.Ссылка = &КонтактЦентр";
			
			Запрос.УстановитьПараметр("КонтактЦентр", ТекЦентр.Ссылка);
			
			РезультатЗапроса = ОбщегоНазначения.ВыполнитьЗапрос(Запрос);
			
			Выборка = РезультатЗапроса.Выбрать();
			Пока Выборка.Следующий() Цикл
				ТекстЗапроса = "
				|SELECT	DISTINCT MemberName AS Телефон
				|FROM	ВнешнийИсточникДанных." + СокрЛП(ТекЦентр.Сервер) + ".Таблица.Агенты
				|WHERE	(queue_name = &Очередь)
				|ORDER	BY Телефон";
				
				Запрос = Новый Запрос;
				Запрос.Текст = ТекстЗапроса;
				Запрос.УстановитьПараметр("Очередь",ВРег(СокрЛП(Выборка.Очередь.Наименование)));
				Попытка
					Результат = Запрос.Выполнить().Выбрать();
				Исключение
					Комментарий = ОписаниеОшибки();
					ЗаписьЖурналаРегистрации("ПриСозданииНаСервере", УровеньЖурналаРегистрации.Ошибка, Метаданные.Обработки.КонсольКонтактЦентра.Формы.ФормаВыбораОператора,,Комментарий);
					Продолжить
				КонецПопытки;
				
				Пока (Результат.Следующий()) Цикл
					ТелСсылка = Конвертация.ТелВнутреннийПолучитьСсылку(Результат.Телефон);
					
					Если (ЗначениеЗаполнено(ТелСсылка)) Тогда
						НовСтрока = ЭтаФорма.Список.Добавить();
						НовСтрока.КонтактЦентр = ТекЦентр.Ссылка;
						НовСтрока.Очередь = Выборка.Очередь;
						НовСтрока.Телефон = ТелСсылка;
					КонецЕсли;
				КонецЦикла;
				
				
			КонецЦикла;
			
		КонецЕсли;
	КонецЦикла;
	
	// Если на данном этапе Список не содержит записей, то завершим работу формы
	//-------------------------------------------------------------------------------------------------
	Если (ЭтаФорма.Список.Количество() = 0) Тогда
		Отказ = Истина;
		Возврат;
	КонецЕсли;
КонецПроцедуры

//-------------------------------------------------------------------------------------------------

&НаКлиенте
Процедура СписокВыбор(Элемент,ВыбраннаяСтрока,Поле,СтандартнаяОбработка)
	СтандартнаяОбработка = Ложь;
	Выбрать(Неопределено);
КонецПроцедуры

&НаКлиенте
Процедура Выбрать(Команда)

// Заполним параметры сеанса реквизитами выбранной записи
//-------------------------------------------------------------------------------------------------
	Если (Элементы.Список.ТекущиеДанные <> Неопределено) Тогда
		СтрПараметры = Новый Структура;
		СтрПараметры.Вставить("Телефон",Элементы.Список.ТекущиеДанные.Телефон);
		СтрПараметры.Вставить("Очередь",Элементы.Список.ТекущиеДанные.Очередь);
		СтрПараметры.Вставить("КонтактЦентр",Элементы.Список.ТекущиеДанные.КонтактЦентр);

		//Установи значение параметров сеанса
		//-----------------------------------
		УстановиЗначениеПараметровСеанса_НаСервере(СтрПараметры);
		
		ЭтаФорма.Закрыть(Истина);
	КонецЕсли;
	
КонецПроцедуры

&НаСервере
Процедура УстановиЗначениеПараметровСеанса_НаСервере(СтрПараметры)
	ПараметрыСеанса.ККЦТелефон = СтрПараметры.Телефон;
	ПараметрыСеанса.ККЦОчередь = СтрПараметры.Очередь;
	ПараметрыСеанса.ККЦКонтактЦентр = СтрПараметры.КонтактЦентр;
КонецПроцедуры
