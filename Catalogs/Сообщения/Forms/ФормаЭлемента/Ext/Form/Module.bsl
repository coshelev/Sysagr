&НаСервере
Процедура УстHTML(ТекстHTML, Вложения)
	Тело.УстановитьHTML(ТекстHTML, Вложения);	
КонецПроцедуры

&НаКлиенте
Процедура ПриОткрытии(Отказ)
	ТекстHTML = Объект.Тело;
	Вложения = Новый Структура();
	
	Сч = 0;
	Для Каждого Зап Из Объект.Вложения Цикл
		Сч = Сч + 1;
		Ключ 		= "image00"+Строка(Сч);
		
		ЗначСтр 		= Зап.Вложение;
		ЗначБин			= Base64Значение(ЗначСтр);
		ЗначКартинка 	= Новый Картинка(ЗначБин);
		
		 Вложения.Вставить(Ключ, ЗначКартинка);
	КонецЦикла;
	УстHTML(ТекстHTML, Вложения);
КонецПроцедуры

&НаКлиенте
Процедура ПередЗаписью(Отказ, ПараметрыЗаписи)
	
	ТекстHTML = "";
	Картинки = Новый Структура;
	ЭтаФорма.Тело.ПолучитьHTML(ТекстHTML, Картинки);

	Объект.Тело = ТекстHTML;
	Объект.Вложения.Очистить();
	Для Каждого Карт Из Картинки Цикл
		Новая = Объект.Вложения.Добавить();
		
		Картинка = Карт.Значение;
		Картинка.Преобразовать(ФорматКартинки.PNG);
		бинари = Картинка.ПолучитьДвоичныеДанные();
		стр = Base64Строка(бинари);	
		
		Новая.Ключ = Карт.Ключ;
		Новая.Вложение = стр;
	КонецЦикла;
КонецПроцедуры




