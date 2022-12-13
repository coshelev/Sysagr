﻿Процедура ЗаполниТЧ_КонтактныеЛица() Экспорт
	
	
	Запрос = Новый Запрос();
	Запрос.Текст = "ВЫБРАТЬ
	               |	КонтактныеЛица.КонтрагентТел КАК КонтрагентТел,
	               |	КонтактныеЛица.СотрудникТел КАК СотрудникТел,
	               |	КонтактныеЛица.КонтактноеЛицо КАК КонтактноеЛицо,
	               |	КонтактныеЛица.Контрагент КАК Контрагент,
	               |	КонтактныеЛица.Сотрудник КАК Сотрудник,
	               |	КонтактныеЛица.Сотрудник1 КАК Сотрудник1,
	               |	КонтактныеЛица.Сотрудник1Тел КАК Сотрудник1Тел,
	               |	КонтактныеЛица.Сотрудник2 КАК Сотрудник2,
	               |	КонтактныеЛица.Сотрудник2Тел КАК Сотрудник2Тел
	               |ИЗ
	               |	РегистрСведений.КонтрагентыВСотрудники КАК КонтактныеЛица";
	Рез = Запрос.Выполнить();
	Если Рез.Пустой() Тогда
		Возврат
	КонецЕсли;
	
	Выб = Рез.Выбрать();
	Пока Выб.Следующий() Цикл
		Новая = ЭтотОбъект.КонтактныеЛица.Добавить();
		ЗаполнитьЗначенияСвойств(Новая, Выб);
	КонецЦикла;
			
КонецПроцедуры

Процедура ЗаполниТЧ_ОтветственныеЗаКонтрагента(ТелНомерВнешнегоАбонента) Экспорт
		
		Отб = Новый Структура();
		Отб.Вставить("КонтрагентТел", ТелНомерВнешнегоАбонента);
		Найденные = ЭтотОбъект.КонтактныеЛица.НайтиСтроки(Отб);
		
		Если Найденные.Количество() = 0 Тогда
			Возврат
		КонецЕсли;
		
		Для Каждого Стр Из Найденные Цикл
			Новая = ЭтотОбъект.ОтветственныеЗаКонтрагента.Добавить();
			ЗаполнитьЗначенияСвойств(Новая, Стр);
		КонецЦикла;
		
	КонецПроцедуры
		
Процедура ЗаполниТЧ_АнкетыРекурсивно() Экспорт
		
		Запрос = Новый Запрос();
		Запрос.Текст = 
		"ВЫБРАТЬ
		|	Спр.Ссылка КАК Вопрос,
		|	Спр.ВариантыОтветов.(
		|		Ответ КАК Ответ,
		|		СледующийВопросИлиТелНомер КАК СледующееДействие,
		|		ВЫБОР
		|			КОГДА ТИПЗНАЧЕНИЯ(Спр.ВариантыОтветов.СледующийВопросИлиТелНомер) = ТИП(Справочник.Анкеты)
		|				ТОГДА 1
		|			КОГДА ТИПЗНАЧЕНИЯ(Спр.ВариантыОтветов.СледующийВопросИлиТелНомер) = ТИП(Справочник.ТелВнутренние)
		|				ТОГДА 2
		|			КОГДА ТИПЗНАЧЕНИЯ(Спр.ВариантыОтветов.СледующийВопросИлиТелНомер) = ТИП(Справочник.ТелОчереди)
		|				ТОГДА 3
		|			КОГДА ТИПЗНАЧЕНИЯ(Спр.ВариантыОтветов.СледующийВопросИлиТелНомер) = ТИП(Справочник.ВиртуальныеОчереди)
		|				ТОГДА 4
		|		КОНЕЦ КАК СледующееДействиеТип,
		|		СледующийВопросИлиТелНомер.Код КАК СледующееДействиеКод,
		|		НомерСтроки КАК НомерСтроки
		|	) КАК ВариантыОтветов
		|ИЗ
		|	Справочник.Анкеты КАК Спр
		|ГДЕ
		|	Спр.ЭтоГруппа = ЛОЖЬ
		|	И Спр.Родитель.Код = ""000000013""
		|
		|УПОРЯДОЧИТЬ ПО
		|	Вопрос,
		|	НомерСтроки";
		
		Рез = Запрос.Выполнить();
		Если Рез.Пустой() Тогда
			Возврат;
		КонецЕсли;
		
		ТЗ = Рез.Выгрузить();
		
		Для Каждого Стр1 Из ТЗ Цикл
			НовыйВопрос = ЭтотОбъект.АнкетаВопросы.Добавить();
			НовыйВопрос.Вопрос = Стр1.Вопрос;
			Для Каждого Стр2 из Стр1.ВариантыОтветов Цикл	
				НовыйОтвет 						= ЭтотОбъект.АнкетаОтветы.Добавить();
				НовыйОтвет.Вопрос 				= НовыйВопрос.Вопрос;
				ЗаполнитьЗначенияСвойств(НовыйОтвет, Стр2);
			КонецЦикла;
		КонецЦикла;
		
	КонецПроцедуры
		
Процедура ЗаполниТЧ_ВыбираемыеОтветы() Экспорт

	Запрос = Новый Запрос();
	Запрос.Текст = 
	"ВЫБРАТЬ
	|	АнкетыВариантыОтветов.Ссылка КАК Вопрос,
	|	АнкетыВариантыОтветов.Ответ КАК Ответ,
	|	АнкетыВариантыОтветов.Картинка КАК Картинка
	|ИЗ
	|	Справочник.Анкеты.ВариантыОтветов КАК АнкетыВариантыОтветов
	|ГДЕ
	|	АнкетыВариантыОтветов.Ссылка.Родитель.Код = ""000000014""";
	
	Рез = Запрос.Выполнить();
	Если Рез.Пустой() Тогда
		Возврат;
	КонецЕсли;
	
	Выб = Рез.Выбрать();
	Пока Выб.Следующий() Цикл
		Новая = ЭтотОбъект.ВыбираемыеОтветы.Добавить();
		ЗаполнитьЗначенияСвойств(Новая, Выб);
	КонецЦикла;

КонецПроцедуры