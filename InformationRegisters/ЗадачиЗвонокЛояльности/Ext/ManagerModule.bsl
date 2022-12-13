﻿Функция Загрузить(	Контрагент, 
					СигнатураПродажи,
					ДатаЗакрытия 		= '00010101', 
					Тип, 
					Исполнитель, 
					Продажа 			= "", 
					Телефон 			= "", 
					Телефоны			= "",
					Комментарий 		= "", 
					ДатаПостановки 		= '00010101', 
					ЗвонокЗакрытия 		= "", 
					ДатаАктуальности 	= '00010101', 
					ПричинаЗакрытия 	= "") Экспорт
	
	Доступно = ТипЗнч(СигнатураПродажи) = Тип("Строка") И ЗначениеЗаполнено(СигнатураПродажи) И ТипЗнч(ДатаЗакрытия) = Тип("Дата") И ТипЗнч(Тип) = Тип("ПеречислениеСсылка.ТипЗадачи");
	Доступно = Доступно И ТипЗнч(Исполнитель) = Тип("СправочникСсылка.КонтактЦентры") Или ТипЗнч(Исполнитель) = Тип("СправочникСсылка.Пользователи") Или ТипЗнч(Исполнитель) = Тип("СправочникСсылка.ТелВнутренние");
	Доступно = Доступно И ТипЗнч(Продажа) = Тип("Строка") И ТипЗнч(Телефон) = Тип("Строка") И ТипЗнч(Телефоны) = Тип("Строка") И ТипЗнч(Комментарий) = Тип("Строка") И ТипЗнч(ДатаПостановки)	= Тип("Дата") И ТипЗнч(ЗвонокЗакрытия) 	= Тип("Строка") И ТипЗнч(ДатаАктуальности) 	= Тип("Дата") И ТипЗнч(ПричинаЗакрытия) = Тип("Строка") И ТипЗнч(Контрагент) = Тип("Строка");  
				
	Запрос = Новый Запрос("ВЫБРАТЬ СигнатураПродажи ИЗ РегистрСведений.ЗадачиЗвонокЛояльности ГДЕ СигнатураПродажи = &СигнатураПродажи");
	Запрос.УстановитьПараметр("СигнатураПродажи", СигнатураПродажи);
	РезультатЗапроса = Запрос.Выполнить();
	Если Не РезультатЗапроса.Пустой() Тогда
		Возврат Ложь;
	КонецЕсли;
	
	НЗ = РегистрыСведений.ЗадачиЗвонокЛояльности.СоздатьМенеджерЗаписи();
	НЗ.СигнатураПродажи = СигнатураПродажи;
	НЗ.ДатаЗакрытия		= ДатаЗакрытия;
	НЗ.Прочитать();
	
	Если НЗ.Выбран() Тогда
		Возврат Ложь;
	КонецЕсли;
	
	НЗ.Контрагент 		= Контрагент;
	НЗ.СигнатураПродажи = СигнатураПродажи;
	НЗ.ДатаЗакрытия 	= ДатаЗакрытия;
	НЗ.Тип 				= Тип;
	НЗ.Телефон 			= Телефон;
	НЗ.Телефоны			= Телефоны;
	НЗ.Исполнитель		= Исполнитель;
	НЗ.Комментарий 		= Комментарий;
	НЗ.ДатаПостановки 	= ДатаПостановки;
	НЗ.ЗвонокЗакрытия 	= ЗвонокЗакрытия;
	НЗ.ДатаАктуальности = ДатаАктуальности;
	НЗ.ПричинаЗакрытия 	= ПричинаЗакрытия;

	Попытка
		НЗ.Записать();
	Исключение
		ЗаписьЖурналаРегистрации("ЗадачиЗвонокЛояльности.Загрузить().Ошибка записи", УровеньЖурналаРегистрации.Ошибка, , ПодробноеПредставлениеОшибки(ИнформацияОбОшибке()));
		Возврат Ложь;
	КонецПопытки;
	
	Возврат Истина
КонецФункции

Функция УстановиЗначениеРеквизитаИЗакройЗадачу(СигнатураПродажи, ДатаЗакрытия, ИмяРеквизита, ЗначениеРеквизита, ТекущийПользователь="") Экспорт
	
	Доступно = ТипЗнч(СигнатураПродажи) = Тип("Строка") И ТипЗнч(ДатаЗакрытия) = Тип("Дата") И ТипЗнч(ИмяРеквизита) = Тип("Строка") И ЗначениеЗаполнено(СигнатураПродажи) И ЗначениеЗаполнено(ДатаЗакрытия) И ЗначениеЗаполнено(ИмяРеквизита);
	Если Не Доступно Тогда
		ЗаписьЖурналаРегистрации("1. РегистрСведений.ЗадачиЗвонокЛояльности.УстановиЗначениеРеквизитаИЗакройЗадачу()", УровеньЖурналаРегистрации.Ошибка, , "СигнатураПродажи="+СигнатураПродажи+"; ДатаЗакрытия="+ДатаЗакрытия+"; ИмяРеквизита= "+ИмяРеквизита, "Не заполнено значение реквизита");
		Возврат Ложь;
	КонецЕсли;
	
	НЗ = РегистрыСведений.ЗадачиЗвонокЛояльности.СоздатьМенеджерЗаписи();
	НЗ.СигнатураПродажи =	СигнатураПродажи;
	НЗ.ДатаЗакрытия		=	Дата("00010101");
	НЗ.Прочитать();
	
	Если Не НЗ.Выбран() Тогда
		ЗаписьЖурналаРегистрации("2. РегистрСведений.ЗадачиЗвонокЛояльности.УстановиЗначениеРеквизитаИЗакройЗадачу()", УровеньЖурналаРегистрации.Ошибка, , "НЗ.СигнатураПродажи="+НЗ.СигнатураПродажи+"; НЗ.ДатаЗакрытия="+НЗ.ДатаЗакрытия, "Не выбрана запись");
		Возврат Ложь;
	КонецЕсли;
	
	ИзмененоЗначениеРеквизита = Ложь;
	НЗ.СигнатураПродажи = НЗ.СигнатураПродажи;
	НЗ.ДатаЗакрытия 	= НЗ.ДатаЗакрытия;
	Для Каждого Рекв Из Метаданные.РегистрыСведений.ЗадачиЗвонокЛояльности.Реквизиты Цикл
		НЗ[Рекв.Имя] = НЗ[Рекв.Имя];
		Если Рекв.Имя <> ИмяРеквизита Тогда
			Продолжить
		КонецЕсли;
		
		Если Не Рекв.Тип.СодержитТип(ТипЗнч(ЗначениеРеквизита)) Тогда
			Продолжить
		КонецЕсли;
		
		НЗ[Рекв.Имя] = ЗначениеРеквизита;
		ИзмененоЗначениеРеквизита = ИСТИНА;
		 
		//Очищаем напоминание перезвонить
		НЗ.НапоминаниеПерезвонить = '00010101';
		 
		Прервать;
	КонецЦикла;
	
	Если Не ИзмененоЗначениеРеквизита Тогда
		Возврат Ложь;
	КонецЕсли;
	
	НЗ.ДатаЗакрытия = ДатаЗакрытия;
	Если ЗначениеЗаполнено(ТекущийПользователь) Тогда
		НЗ.Исполнитель = ТекущийПользователь;
	КонецЕсли;
	
	Попытка
		НЗ.Записать();
	Исключение
		ЗаписьЖурналаРегистрации("3. РегистрСведений.ЗадачиЗвонокЛояльности.УстановиЗначениеРеквизитаИЗакройЗадачу()", УровеньЖурналаРегистрации.Ошибка,,, ПодробноеПредставлениеОшибки(ИнформацияОбОшибке()));
		Возврат Ложь;
	КонецПопытки;
		
	Возврат Истина;
		
КонецФункции

Функция ЗакрытьПричинойРучногоЗакрытия(СигнатураПродажи, ДатаЗакрытия, ПричинаЗакрытия, Комментарий = "", ТекущийПользователь="") Экспорт
	//Закрывает открытую задачу переданными причиной ручного закрытия и датой закрытия
	//---------------------------------------------------------------------------------
	
	Доступно = ТипЗнч(СигнатураПродажи) = Тип("Строка") И ТипЗнч(ДатаЗакрытия) = Тип("Дата") И ТипЗнч(ПричинаЗакрытия) = Тип("Строка") И ЗначениеЗаполнено(СигнатураПродажи) И ЗначениеЗаполнено(ДатаЗакрытия) И ЗначениеЗаполнено(ПричинаЗакрытия);
	Если Не Доступно Тогда
		ЗаписьЖурналаРегистрации("АвтозакрытиеНовойЗадачей", УровеньЖурналаРегистрации.Ошибка, , "СигнатураПродажи=" + СигнатураПродажи + "; ДатаЗакрытия=" + ДатаЗакрытия + "; ПричинаЗакрытия= " + ПричинаЗакрытия, "Не заполнено значение реквизита");
		Возврат Ложь;
	КонецЕсли;
	
	НЗ = РегистрыСведений.ЗадачиЗвонокЛояльности.СоздатьМенеджерЗаписи();
	НЗ.СигнатураПродажи =	СигнатураПродажи;
	НЗ.ДатаЗакрытия		=	Дата("00010101");
	НЗ.Прочитать();
	
	Если Не НЗ.Выбран() Тогда
		ЗаписьЖурналаРегистрации("АвтозакрытиеНовойЗадачей", УровеньЖурналаРегистрации.Ошибка, , "НЗ.СигнатураПродажи="+НЗ.СигнатураПродажи+"; НЗ.ДатаЗакрытия="+НЗ.ДатаЗакрытия, "Не выбрана запись");
		Возврат Ложь;
	КонецЕсли;
	
	НЗ.ПричинаЗакрытия 	= ПричинаЗакрытия;
	Если ЗначениеЗаполнено(Комментарий) Тогда
		НЗ.Комментарий = НЗ.Комментарий + ?(ЗначениеЗаполнено(НЗ.Комментарий), "; ", "")+ Комментарий;
	КонецЕсли;	
	
	НЗ.ДатаЗакрытия = ДатаЗакрытия;
	
	Если ЗначениеЗаполнено(ТекущийПользователь) Тогда
		НЗ.Исполнитель = ТекущийПользователь;
	КонецЕсли;
	
	Попытка
		НЗ.Записать();
	Исключение
		ЗаписьЖурналаРегистрации("АвтозакрытиеНовойЗадачей", УровеньЖурналаРегистрации.Ошибка, , , ОписаниеОшибки());
		Возврат Ложь;
	КонецПопытки;
		
	Возврат Истина;	
КонецФункции

Функция УстановиЗначениеРеквизита(СигнатураПродажи, ИмяРеквизита, СтароеЗначение, НовоеЗначение, ДатаЗакрытия='00010101000000', НоваяДатаЗакрытия='00010101000000') Экспорт
	
	Доступно = ТипЗнч(СигнатураПродажи) = Тип("Строка") И ТипЗнч(ИмяРеквизита) = Тип("Строка") И ЗначениеЗаполнено(СигнатураПродажи)  И ЗначениеЗаполнено(НовоеЗначение);	
	Если Не Доступно Тогда
		Возврат Ложь;
	КонецЕсли;
	
	НЗ = РегистрыСведений.ЗадачиЗвонокЛояльности.СоздатьМенеджерЗаписи();
	НЗ.СигнатураПродажи = СигнатураПродажи;
	НЗ.ДатаЗакрытия 	= ДатаЗакрытия;
	НЗ.Прочитать();
	
	Если Не НЗ.Выбран() Тогда
		Возврат Ложь
	КонецЕсли;
 
	НЗ.СигнатураПродажи = СигнатураПродажи;
	НЗ.ДатаЗакрытия 	= НоваяДатаЗакрытия;
	
	Для Каждого Рекв Из Метаданные.РегистрыСведений.ЗадачиЗвонокЛояльности.Реквизиты Цикл
		Если Рекв.Имя = ИмяРеквизита Тогда
			 НЗ[Рекв.Имя] = НовоеЗначение;
		Иначе
			НЗ[Рекв.Имя] = НЗ[Рекв.Имя];
		КонецЕсли;
	КонецЦикла;
	
	НЗ.Комментарий = НЗ.Комментарий + Символы.ПС+" "+ТекущаяДата()+" изменен "  +ИмяРеквизита+ " с "+СтароеЗначение+" на "+НовоеЗначение+" пользователем "+ПараметрыСеанса.ТекущийПользователь;
	
	Попытка
		НЗ.Записать();
	Исключение
		ЗаписьЖурналаРегистрации("4. РегистрСведений.ЗадачиЗвонокЛояльности.УстановиЗначениеРеквизита()", УровеньЖурналаРегистрации.Ошибка, ,, "Ошибка записи");
		Возврат Ложь;
	КонецПопытки;
	
	Возврат Истина;

КонецФункции

Функция ПерезакройЗакрытуюЗадачуПричинойРучногоЗакрытия(СигнатураПродажи, ДатаПереЗакрытия, ПричинаЗакрытия, Пользователь="") Экспорт
	//Вызывается в случае, если задача была закрыта анкетой, но при прослушке поняли, что неверно закрыли, поэтому перезакрываем причиной ручного закрытия
	//Дата закрытия не меняется, дата перезакрытия фиксируестя только в комментарии 
	//-----------------------------------------------------------------------------------------------------------------------------------------------------
	
	Данные = СтрШаблон("СигнатураПродажи = %1; ДатаПереЗакрытия = %2; ПричинаЗакрытия = %3; ТекущийПользователь = %4", СигнатураПродажи, ДатаПереЗакрытия, ПричинаЗакрытия, Пользователь);
	
	Доступно = 		ТипЗнч(СигнатураПродажи) = Тип("Строка") И ТипЗнч(ДатаПереЗакрытия) = Тип("Дата") И ТипЗнч(ПричинаЗакрытия) = Тип("Строка") 
				И 	ЗначениеЗаполнено(СигнатураПродажи) И ЗначениеЗаполнено(ДатаПереЗакрытия) И ЗначениеЗаполнено(ПричинаЗакрытия);	
	Если Не Доступно Тогда
		ЗаписьЖурналаРегистрации("1. РегистрСведений.ЗадачиЗвонокЛояльности.ПерезакройЗакрытуюЗадачуПричинойРучногоЗакрытия", УровеньЖурналаРегистрации.Ошибка, , Данные, "неверные параметры");
		Возврат "ошибка: неверные параметры";
	КонецЕсли;
	
	Запрос = Новый Запрос("ВЫБРАТЬ ДатаЗакрытия ИЗ РегистрСведений.ЗадачиЗвонокЛояльности ГДЕ СигнатураПродажи = &СигнатураПродажи И ДатаЗакрытия <> ДАТАВРЕМЯ(1, 1, 1)");
	Запрос.УстановитьПараметр("СигнатураПродажи", СигнатураПродажи);
	РезультатЗапроса = Запрос.Выполнить();
	Если РезультатЗапроса.Пустой() Тогда
		Возврат "ошибка: не найдена дата закрытия задачи";	
	КонецЕсли;
	ДатаЗакрытия = РезультатЗапроса.Выгрузить()[0][0];
	
	Зап = РегистрыСведений.ЗадачиЗвонокЛояльности.СоздатьМенеджерЗаписи();
	Зап.СигнатураПродажи =	СигнатураПродажи;
	Зап.ДатаЗакрытия	 =	ДатаЗакрытия;
	Зап.Прочитать();
	
	Если Не Зап.Выбран() Тогда
		ЗаписьЖурналаРегистрации("2. РегистрСведений.ЗадачиЗвонокЛояльности.ПерезакройЗакрытуюЗадачуПричинойРучногоЗакрытия()", УровеньЖурналаРегистрации.Ошибка, , Данные, "Не выбрана запись");
		Возврат "ошибка: не выбрана запись";
	КонецЕсли;
	
	Зап.СигнатураПродажи 	= СигнатураПродажи;
	Зап.ПричинаЗакрытия 	= ПричинаЗакрытия; 
	Зап.ДатаЗакрытия		= ДатаЗакрытия;
	Зап.Комментарий			= Зап.Комментарий+СтрШаблон("Перезакрыта %1 причиной ручного закрытия пользователем %2", ДатаПереЗакрытия, Пользователь); 
	
	Попытка
		Зап.Записать();
	Исключение
		ЗаписьЖурналаРегистрации("3.РегистрСведений.ЗадачиЗвонокЛояльности.ПерезакройЗакрытуюЗадачуПричинойРучногоЗакрытия()", УровеньЖурналаРегистрации.Ошибка, , Данные, ПодробноеПредставлениеОшибки(ИнформацияОбОшибке()));
		Возврат "ошибка: при записи";
	КонецПопытки;
		
	Возврат "";
КонецФункции
