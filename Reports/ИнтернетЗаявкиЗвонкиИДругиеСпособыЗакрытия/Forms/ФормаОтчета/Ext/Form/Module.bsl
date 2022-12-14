&НаСервере
Процедура ПриСозданииНаСервере(Отказ, СтандартнаяОбработка)
	//Если отчет открывается в режиме расшифровки основного, то ПриСозданииНаСервере доступны параметры основного отчета, а ПриОткрытии() - уже нет, т.к. не являются ключевыми
	Элементы.Вариант.СписокВыбора.Добавить("ЗвонкиВсеПоИнтернетЗаявкам",		"Все (состоявшиеся и несостоявшиеся) заявки");     
	Элементы.Вариант.СписокВыбора.Добавить("ЗвонкиВсеПоИнтернетЗаявкамДетально","Все (состоявшиеся и несостоявшиеся) заявки детально (на одну заявку может быть несколько звонков)");  
	Элементы.Вариант.СписокВыбора.Добавить("ЗвонкиНесостоявшиесяПоИнтернетЗаявкамСводно","Несостоявшиеся заявки - история дальнейшей обработки сводно");  
	Элементы.Вариант.СписокВыбора.Добавить("ЗвонкиНесостоявшиесяПоИнтернетЗаявкамДетально","Несостоявшиеся заявки - история дальнейшей обработки детально");  
	
	//Если открываемый отчет - расшифровка основного отчета, установи период из основного отчета
	Прд = "";
	Доступно = Параметры.Свойство("Период", Прд) И ЗначениеЗаполнено(Параметры.Период.ДатаОкончания);
	Если Доступно Тогда
		Отчет.Период.ДатаОкончания  = Параметры.Период.ДатаОкончания;
		Отчет.Период.ДатаНачала 	= Параметры.Период.ДатаНачала;	
	КонецЕсли;
	
	//Если открываемый отчет - расшифровка основного отчета, установи вариант как в основном отчете
	Вар = "";
	Доступно = Параметры.Свойство("ТекВариант", Вар) И ЗначениеЗаполнено(Параметры.ТекВариант);
	Если Доступно Тогда
		Отчет.ТекВариант = Параметры.ТекВариант;
	Иначе
		//Вариант по умолчанию, при вызове отчета из меню
		Отчет.ТекВариант = "ЗвонкиВсеПоИнтернетЗаявкам";
	КонецЕсли;
	
	Элементы.ГруппаПрочее.Видимость = Истина;
	ВариантОбработкаВыбораНаСервере(Отчет.ТекВариант);	
КонецПроцедуры

&НаКлиенте
Процедура ВидимостьНастроек(Команда)
	Элементы.ГруппаСтраницы.Видимость = НЕ Элементы.ГруппаСтраницы.Видимость;
	ОбновитьОтображение();
КонецПроцедуры

&НаКлиенте
Процедура ПриОткрытии(Отказ)
	
	Если ЗначениеЗаполнено(Отчет.Период.ДатаОкончания) Тогда
		Отчет.Период.ДатаОкончания 	= Отчет.Период.ДатаОкончания;
		Отчет.Период.ДатаНачала 	= Отчет.Период.ДатаНачала;	
	Иначе
		Отчет.Период.ДатаОкончания 	= КонецДня(НачалоДня(ТекущаяДата())-1);
		Отчет.Период.ДатаНачала		= НачалоМесяца(Отчет.Период.ДатаОкончания);
	КонецЕсли;
	
	Элементы.ГруппаСтраницы.Видимость = Ложь;	
	ОбновитьОтображение();
КонецПроцедуры

&НаКлиенте
Процедура ВыборПериода(Команда)
	Диалог = Новый ДиалогРедактированияСтандартногоПериода(); 
	Диалог.Период = Отчет.Период; 
	
	Если Диалог.Редактировать() Тогда 
		Отчет.Период = Диалог.Период; 
	КонецЕсли;
	
	ОбновитьОтображение();

КонецПроцедуры

&НаКлиенте
Процедура ОбновитьОтображение()
	Элементы.ВыборПериода.Заголовок = " "+Формат(Отчет.Период.ДатаНачала, "ДЛФ=Д")+" - "+Формат(Отчет.Период.ДатаОкончания, "ДЛФ=Д");
	Элементы.ВидимостьНастроек.Пометка = Элементы.ГруппаСтраницы.Видимость;
КонецПроцедуры

&НаСервере
Процедура ПередЗагрузкойВариантаНаСервере(Настройки)
	//Вставить содержимое обработчика
КонецПроцедуры

&НаСервере
Процедура ПриЗагрузкеВариантаНаСервере(Настройки)
	//КонтрольДоступа.УстановитьОтборПоДоступнымТочкамОформленияВОтчете(Настройки, Отчет.КомпоновщикНастроек);       
	//КонтрольДоступа.УстановитьМакетОформленияОтчета(Настройки, Отчет.КомпоновщикНастроек);
КонецПроцедуры

#Область Расшифровка
&НаКлиенте
Процедура РезультатОбработкаРасшифровки(Элемент, Расшифровка, СтандартнаяОбработка, ДополнительныеПараметры)
	
	Расш = РезультатОбработкаРасшифровкиНаСервере(Расшифровка);    
	Если Не ЗначениеЗаполнено(Расш.Поле) Тогда
		Возврат
	КонецЕсли;
	
	//Если пользователь пытается открыть список звонков
	//--------------------------------------------------
	Доступно = Расш.Поле = "Звонок" И ЗначениеЗаполнено(Расш.Значение);
	Если Доступно Тогда
		СтандартнаяОбработка = Ложь;
		Парам = Новый Структура("Отбор", Новый Структура("Сигнатура", Расш.Значение)); 
    	ОткрытьФорму("РегистрСведений.Звонки.ФормаСписка", Парам);
		Возврат;	 	
	КонецЕсли;    

КонецПроцедуры

&НаСервере
Функция РезультатОбработкаРасшифровкиНаСервере(Расшифровка)
	Перем Рез;
	Рез = Новый Структура("Поле, Значение", " "", """);
	
	РасшифровкаОтчета = ПолучитьИзВременногоХранилища(ЭтаФорма.ДанныеРасшифровки);
	ЭлементыРасшифровки = РасшифровкаОтчета.Элементы;
	РасшифровкаЯчейки =  ЭлементыРасшифровки.Получить(Расшифровка);
	ЗначенияПолейРасш = РасшифровкаЯчейки.ПолучитьПоля();
	ЗначениеПоляРасш = ЗначенияПолейРасш.Получить(0);
	
	ЗаполнитьЗначенияСвойств(Рез, ЗначениеПоляРасш);
	Возврат Рез;
КонецФункции
#КонецОбласти

&НаКлиенте
Процедура ПередЗакрытием(Отказ, ЗавершениеРаботы, ТекстПредупреждения, СтандартнаяОбработка)
	СтандартнаяОбработка = Ложь;
КонецПроцедуры

#Область Выбор_варианта
&НаСервере
Процедура ВариантОбработкаВыбораНаСервере(ИмяВарианта)
	Результат.Очистить();
	
	Об 							= РеквизитФормыВЗначение("Отчет");
	СхемаКомпоновкиДанных 		= РеквизитФормыВЗначение("Отчет").ПолучитьСКД(ИмяВарианта, "C:\Users\Public\Documents\"+ИмяВарианта+".xml");
	АдресВремХран				= ПоместитьВоВременноеХранилище(СхемаКомпоновкиДанных, УникальныйИдентификатор);
	ИсточникДоступныхНастроек 	= Новый ИсточникДоступныхНастроекКомпоновкиДанных(АдресВремХран);
	Отчет.КомпоновщикНастроек.Инициализировать(ИсточникДоступныхНастроек);
	Отчет.КомпоновщикНастроек.ЗагрузитьНастройки(СхемаКомпоновкиДанных.НастройкиПоУмолчанию);
КонецПроцедуры

&НаКлиенте
Процедура ВариантОбработкаВыбора(Элемент, ВыбранноеЗначение, СтандартнаяОбработка)
	ВариантОбработкаВыбораНаСервере(ВыбранноеЗначение)
КонецПроцедуры
#КонецОбласти




 
